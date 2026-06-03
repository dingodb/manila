import abc
import json
import math
import shlex
import socket

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import strutils
from oslo_utils import units
from oslo_log import log


from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.helpers import NFSHelper
from manila.share import share_types
from manila import ssh_utils
from manila import utils

LOG = log.getLogger(__name__)

dingofs_share_opts = [
    cfg.HostAddressOpt('dingofs_share_export_ip',
                       help='IP to be added to Dingofs export string.'),
    cfg.StrOpt('dingofs_fs_name',
               default='alayanew',
               help='DingoFS filesystem name.'),
    cfg.StrOpt('fs_mount_point_base',
               default='/dinogfs/alayanew',
               help='Base folder where exported shares are located.'),
    cfg.StrOpt('dingofs_nfs_server_type',
               default='VFS',
               help=('NFS Server type. Valid choices are "VFS" (Ganesha NFS) ')),
    cfg.BoolOpt('dingofs_enable_export',
                default=False,
                help=('Whether to manage NFS exports via the "dingo export" '
                      'commands when granting/revoking access. Requires '
                      'Ganesha NFS to be deployed on the DingoFS node. '
                      'Defaults to False because DingoFS does not install '
                      'Ganesha by default; when disabled, access rules are '
                      'accepted but no "dingo export" command is executed.')),
    cfg.BoolOpt('is_dingofs_node',
                default=False,
                help=('True:when Manila services are running on one of the '
                      'Dingofs node. '
                      'False:when Manila services are not running on any of '
                      'Dingofs node.')),
    cfg.PortOpt('dingofs_ssh_port',
                default=22,
                help='DingoFS server SSH port.'),
    cfg.ListOpt('dingofs_share_helpers',
                default=[
                    'VFS=manila.share.drivers.dingofs.driver.VFSHelper',
                ],
                help='Specify list of share export helpers.'),
    cfg.StrOpt('dingofs_ssh_login',
               help='DingoFS server SSH login name.'),
    cfg.StrOpt('dingofs_ssh_password',
               secret=True,
               help='DingoFS server SSH login password. '
                    'The password is not needed, if \'dingofs_ssh_private_key\' '
                    'is configured.'),
    cfg.StrOpt('dingofs_ssh_private_key',
               help='Path to DingoFS server SSH private key for login.'),
    cfg.IntOpt('dingofs_ssh_cmd_timeout',
               default=120,
               help='Timeout in seconds for a single "dingo" command '
                    'executed over SSH. Prevents a hung command from '
                    'blocking the manila-share worker indefinitely.'),
]

class DingoFSShareDriver(driver.ExecuteMixin, driver.GaneshaMixin,
                      driver.ShareDriver):
    """DingoFS Share Driver.
    Executes commands relating to DingoFS shares.
    """
    def __init__(self, *args, **kwargs):
        super(DingoFSShareDriver, self).__init__(False, *args, **kwargs)
        self._helpers = {}
        self.configuration.append_config_values(dingofs_share_opts)
        self.fs_name = self.configuration.dingofs_fs_name
        self.fs_mount_point_base = self.configuration.fs_mount_point_base
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'DingoFS'
        self.sshpool = None
        self.ssh_connections = {}
        self._dingo_execute = None
        self.DINGO_TOOL_PATH = 'dingo'


    def do_setup(self, context):
        """Any initialization the DingoFS driver does while starting."""
        super(DingoFSShareDriver, self).do_setup(context)
        if self.configuration.is_dingofs_node:
            self._dingo_execute = self._dingo_local_execute
        else:
            self._dingo_execute = self._dingo_remote_execute
        self._setup_helpers()

    def _dingo_local_execute(self, *cmd, **kwargs):
        """Execute a command on the local DingoFS node."""
        if 'run_as_root' not in kwargs:
            kwargs.update({'run_as_root': True})
        if 'ignore_exit_code' in kwargs:
            check_exit_code = kwargs.pop('ignore_exit_code')
            check_exit_code.append(0)
            kwargs.update({'check_exit_code': check_exit_code})
        return utils.execute(*cmd, **kwargs)

    def _dingo_remote_execute(self, *cmd, **kwargs):
        host = self.configuration.dingofs_share_export_ip
        check_exit_code = kwargs.pop('check_exit_code', True)
        ignore_exit_code = kwargs.pop('ignore_exit_code', None)
        return self._run_ssh(host, cmd, ignore_exit_code, check_exit_code)

    def _run_ssh(self, host, cmd_list, ignore_exit_code=None,
                 check_exit_code=True):
        command = self._sanitize_command(cmd_list)
        if not self.sshpool:
            dingofs_ssh_login = self.configuration.dingofs_ssh_login
            password = self.configuration.dingofs_ssh_password
            privatekey = self.configuration.dingofs_ssh_private_key
            dingofs_ssh_port = self.configuration.dingofs_ssh_port
            ssh_conn_timeout = self.configuration.ssh_conn_timeout
            min_size = self.configuration.ssh_min_pool_conn
            max_size = self.configuration.ssh_max_pool_conn

            self.sshpool = ssh_utils.SSHPool(host,
                                             dingofs_ssh_port,
                                             ssh_conn_timeout,
                                             dingofs_ssh_login,
                                             password=password,
                                             privatekey=privatekey,
                                             min_size=min_size,
                                             max_size=max_size)
        try:
            with self.sshpool.item() as ssh:
                return self._dingofs_ssh_execute(
                    ssh,
                    command,
                    ignore_exit_code=ignore_exit_code,
                    check_exit_code=check_exit_code)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                msg = (_('Error running SSH command: %(cmd)s. '
                         'Error: %(excmsg)s.') %
                       {'cmd': command, 'excmsg': e})
                LOG.error(msg)
                raise exception.DingoFSException(msg)

    def _dingofs_ssh_execute(self, ssh, cmd, ignore_exit_code=None,
                                check_exit_code=True):
            """Execute a command on a remote DingoFS node via SSH."""
            sanitized_cmd = strutils.mask_password(cmd)
            LOG.debug('Running cmd (SSH): %s', sanitized_cmd)

            # Wrap command with bash login shell to load /etc/profile and
            # user environment variables, since SSH exec_command runs in
            # non-interactive non-login shell by default.
            wrapped_cmd = 'bash -l -c %s' % shlex.quote(cmd)
            LOG.debug('Wrapped cmd (SSH): %s',wrapped_cmd)
            # A per-command timeout bounds both a hung command and the
            # classic paramiko stdout/stderr read deadlock: read() will
            # raise socket.timeout instead of blocking the worker forever.
            timeout = self.configuration.dingofs_ssh_cmd_timeout
            try:
                stdin_stream, stdout_stream, stderr_stream = ssh.exec_command(
                    wrapped_cmd, timeout=timeout)
                channel = stdout_stream.channel

                stdout = stdout_stream.read()
                stderr = stderr_stream.read()
                stdin_stream.close()
            except socket.timeout:
                msg = (_('DingoFS command timed out after %(timeout)ss: '
                         '%(cmd)s') %
                       {'timeout': timeout, 'cmd': sanitized_cmd})
                LOG.error(msg)
                raise exception.DingoFSException(msg)

            def _to_text(val):
                # Normalize bytes/str output to text. Do not unescape "\n"
                # here: that would corrupt legitimate backslash sequences in
                # command output (e.g. JSON from "config get").
                if isinstance(val, bytes):
                    return val.decode('utf-8', 'ignore')
                return str(val)

            stdout = _to_text(stdout)
            stderr = _to_text(stderr)

            sanitized_stdout = strutils.mask_password(stdout)
            sanitized_stderr = strutils.mask_password(stderr)

            exit_status = channel.recv_exit_status()
            LOG.debug('Result was %s', exit_status)

            # exit_status == -1 means the channel closed without returning an
            # exit code; treat it as a failure rather than silently succeeding.
            check_failed = (
                exit_status == -1
                or (exit_status != 0
                    and (ignore_exit_code is None
                         or exit_status not in ignore_exit_code)))
            if check_exit_code and check_failed:
                raise exception.ProcessExecutionError(
                    exit_code=exit_status,
                    stdout=sanitized_stdout,
                    stderr=sanitized_stderr,
                    cmd=sanitized_cmd)

            return (sanitized_stdout, sanitized_stderr)

    def _check_dingo_result(self, out, operation, sharename):
        """Best-effort sanity check on a dingo command's stdout.

        Success/failure is determined by the command exit code (a non-zero
        exit raises ProcessExecutionError in the executor). The output is
        only inspected as a secondary diagnostic: a missing "success" token
        is logged as a warning but does NOT fail the operation, since the
        dingo CLI may succeed silently or print to stderr.
        """
        if out is None or 'success' not in out.lower():
            LOG.warning('%(operation)s for DingoFS share %(sharename)s '
                        'exited successfully but output did not contain '
                        '"success". Output: %(out)s',
                        {'operation': operation, 'sharename': sharename,
                         'out': out})

    @staticmethod
    def _error_output_contains(e, keywords):
        """Return True if a ProcessExecutionError's output mentions a keyword.

        Used to make create/delete idempotent by recognising "already
        exists" / "not found" style messages from the dingo CLI.
        """
        text = ('%s %s' % (getattr(e, 'stdout', '') or '',
                           getattr(e, 'stderr', '') or '')).lower()
        return any(kw in text for kw in keywords)

    def _create_share(self, shareobj):
        sharename = shareobj['name']
        # Convert size to string (unit is GB)
        sizestr = str(shareobj['size'])
        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'create', 'subpath', '--fsname', self.fs_name,
                                          '--path', '/%s' % sharename)
            self._check_dingo_result(out, 'Create subpath', sharename)
        except exception.ProcessExecutionError as e:
            # Idempotency: an already-existing subpath is not an error, the
            # operation may be a retry of a previously interrupted create.
            if self._error_output_contains(e, ('already exist', 'exists')):
                LOG.info('DingoFS subpath for share %s already exists, '
                         'treating create as idempotent.', sharename)
            else:
                msg = (_('Failed to create DingoFS share %(sharename)s. '
                         'Error: %(excmsg)s.') %
                       {'sharename': sharename,
                        'excmsg': e})
                LOG.error(msg)
                raise exception.DingoFSException(msg)

        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'quota', 'set', '--fsname', self.fs_name,
                                          '--path', '/%s' % sharename, '--capacity', sizestr)
            self._check_dingo_result(out, 'Set quota', sharename)
        except exception.ProcessExecutionError as e:
            # Roll back the subpath we just created so we don't leave an
            # orphaned directory that would break a later retry.
            LOG.error('Failed to set quota for DingoFS share %s, rolling '
                      'back the created subpath.', sharename)
            try:
                self._delete_share(shareobj)
            except Exception:
                LOG.exception('Rollback of subpath for share %s failed; '
                              'manual cleanup may be required.', sharename)
            msg = (_('Failed to set quota for DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename,
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)
    def _delete_share(self, shareobj):
        sharename = shareobj['name']
        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'delete', 'subpath', '--fsname', self.fs_name,
                                          '--path', '/%s' % sharename)
            self._check_dingo_result(out, 'Delete subpath', sharename)
        except exception.ProcessExecutionError as e:
            # Idempotency: a missing subpath means it is already deleted.
            if self._error_output_contains(
                    e, ('not found', 'not exist', 'no such', 'does not exist')):
                LOG.info('DingoFS subpath for share %s not found, treating '
                         'delete as idempotent.', sharename)
                return
            msg = (_('Failed to delete DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename,
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)

    def _extend_share(self, share, new_size, share_server=None):
        sharename = share['name']
        # Convert size to string (unit is GB)
        sizestr = str(new_size)
        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'quota', 'set', '--fsname', self.fs_name,
                                          '--path', '/%s' % sharename, '--capacity', sizestr)
            self._check_dingo_result(out, 'Extend quota', sharename)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to extend quota for DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename,
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)
    def _get_share_path(self, share):
        return '/%s' % share['name']

    def create_share(self, context, share, share_server=None):
        """Creates a DingoFS share."""
        self._create_share(share)
        share_path = '%s/%s' % (self.fs_mount_point_base, share['name'])
        location = self._get_helper(share).create_export(share_path)
        return location
    def create_share_from_snapshot(self, ctx, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create share from a snapshot."""
        pass

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        pass

    def delete_share(self, ctx, share, share_server=None):
        """Remove and cleanup share storage."""
        location = self._get_share_path(share)
        self._get_helper(share).remove_export(location, share)
        self._delete_share(share)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        pass

    def extend_share(self, share, new_size, share_server=None):
        """Extends the quota on the share fileset."""
        self._extend_share(share, new_size)

    def ensure_share(self, ctx, share, share_server=None):
        """Ensure that storage are mounted and exported."""

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for share."""
        helper = self._get_helper(share)
        location = share['name']
        for access in delete_rules:
            helper.deny_access(location, share, access)

        for access in add_rules:
            helper.allow_access(location, share, access)

        if not (add_rules or delete_rules):
            helper.resync_access(location, share, access_rules)

    def check_for_setup_error(self):
        """Checks for errors in the setup of a DingoFS share."""
        if not self._check_dingofs_state():
            msg = (_('DingoFS is not active.'))
            LOG.error(msg)
            raise exception.DingoFSException(msg)

        if not self.configuration.dingofs_share_export_ip:
            msg = (_('The configuration option '
                     'dingofs_share_export_ip is not set.'))
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)
        fs_name = self.configuration.dingofs_fs_name
        if not self._is_dingofs_fs(fs_name):
            msg = (_('DingoFS filesystem %(fs_name)s does not exist.') %
                   {'fs_name': fs_name})
            LOG.error(msg)
            raise exception.DingoFSException(msg)


    def _check_dingofs_state(self):
        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'status', 'mds')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check DingoFS state. Error: %(excmsg)s.') %
                    {'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)
        lines = out.splitlines()
        for line in lines:
            if 'online' in line:
                return True

        return False


    def _is_dingofs_fs(self, fs_name):
        try:
            out, __ = self._dingo_execute(self.DINGO_TOOL_PATH, 'query', 'fs', '--fsname', fs_name)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to list DingoFS filesystems. Error: %(excmsg)s.') %
                    {'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)
        # Output is a table format, check if fs_name appears in the output
        # and the filesystem status is NORMAL
        lines = out.splitlines()
        for line in lines:
            # Check if line contains the fs_name and NORMAL status
            if fs_name in line and 'NORMAL' in line:
                return True
        return False

    def _get_available_capacity(self, fs_name):
        """Get available capacity of the DingoFS file system.

        Returns:
            tuple: (free_bytes, total_bytes)
        """
        try:
            out, __ = self._dingo_execute(
                self.DINGO_TOOL_PATH, 'config', 'get',
                '--fsname', self.fs_name, '--format', 'json')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to get DingoFS capacity. Error: %(excmsg)s.') %
                   {'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)

        try:
            data = json.loads(out)
            quota = data['result']['quota']
            max_bytes = int(quota['maxBytes'])
            used_bytes = int(quota['usedBytes'])
            free_bytes = max_bytes - used_bytes
            return free_bytes, max_bytes
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            msg = (_('Failed to parse DingoFS capacity response. '
                     'Error: %(excmsg)s. Response: %(response)s') %
                   {'excmsg': e, 'response': out})
            LOG.error(msg)
            raise exception.DingoFSException(msg)

    def _update_share_stats(self):
        """Retrieve stats info from share volume group."""

        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='DingoFS',
            storage_protocol='NFS',
            reserved_percentage=self.configuration.reserved_share_percentage,
            reserved_snapshot_percentage=(
                self.configuration.reserved_share_from_snapshot_percentage
                or self.configuration.reserved_share_percentage),
            reserved_share_extend_percentage=(
                self.configuration.reserved_share_extend_percentage
                or self.configuration.reserved_share_percentage))

        # Degrade gracefully: a transient failure to read capacity must not
        # raise out of the periodic stats task, otherwise the whole backend
        # would flap as unavailable / un-schedulable on every cycle.
        try:
            free, capacity = self._get_available_capacity(
                self.configuration.dingofs_fs_name)
            data['total_capacity_gb'] = math.ceil(capacity / units.Gi)
            data['free_capacity_gb'] = math.ceil(free / units.Gi)
        except exception.DingoFSException as e:
            LOG.warning('Failed to update DingoFS capacity stats, reporting '
                        'unknown capacity this cycle. Error: %s', e)
            data['total_capacity_gb'] = 'unknown'
            data['free_capacity_gb'] = 'unknown'

        super(DingoFSShareDriver, self)._update_share_stats(data)


    def _get_helper(self, share):
        if share['share_proto'] == 'NFS':
            return self._helpers[self.configuration.dingofs_nfs_server_type]
        else:
            msg = (_('Share protocol %s not supported by DingoFS driver.')
                   % share['share_proto'])
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.dingofs_share_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            self._helpers[share_proto.upper()] = helper(self._dingo_execute,
                                                        self.configuration)
    def _sanitize_command(self, cmd_list):
        # pylint: disable=too-many-function-args
        return ' '.join(shlex.quote(cmd_arg) for cmd_arg in cmd_list)

class DingoFSNFSHelper(metaclass=abc.ABCMeta):
    """Abstract DingoFS NFS Helper Base Class."""
    def __init__(self, execute, configuration):
        self._execute = execute
        self.configuration = configuration

    def create_export(self, share_path):
        """Create and return export location for the given share path."""
        return ':'.join([self.configuration.dingofs_share_export_ip, share_path])

    @abc.abstractmethod
    def remove_export(self, share_path, share):
        """Remove export for the given share path."""

    @abc.abstractmethod
    def get_access_option(self, access):
        """Get access option string based on access level."""

    @abc.abstractmethod
    def allow_access(self, local_path, share, access):
        """Allow access to the host."""

    @abc.abstractmethod
    def deny_access(self, local_path, share, access):
        """Deny access to the host."""

    @abc.abstractmethod
    def resync_access(self, local_path, share, access_rules):
        """Re-sync all access rules for given share."""

    @abc.abstractmethod
    def _get_options_not_allowed(self):
        """Get access options that are not allowed in extra-specs."""

    def _validate_export_options(self, options):
        """Validate the export options."""
        options_not_allowed = self._get_options_not_allowed()
        invalid_options = [
            option for option in options if option in options_not_allowed
        ]

        if invalid_options:
            raise exception.InvalidInput(reason='Invalid export_option %s as '
                                                'it is set by access_type.'
                                                % invalid_options)

    def _get_validated_opt_list(self, export_options):
        """Validate the export options and return an option list."""
        if export_options:
            options = export_options.lower().split(',')
            self._validate_export_options(options)
        else:
            options = []
        return options

    def get_export_options(self, share, access, helper):
        """Get the export options.

        Returns NFS export config string in format: IP(options)
        Example: "192.168.1.1(Access_Type=RW)" or "192.168.1.1/24(Access_Type=RW)"
        """
        extra_specs = share_types.get_extra_specs_from_share(share)
        if helper == 'VFS':
            export_options = extra_specs.get('vfs:export_options')
        else:
            export_options = None

        options = self._get_validated_opt_list(export_options)
        options.append(self.get_access_option(access))

        # Get client IP from access rule
        client_ip = access['access_to']
        # Format: IP(option1,option2,...)
        return '%s(%s)' % (client_ip, ','.join(options))

class VFSHelper(DingoFSNFSHelper):
    """DingoFS VFS Helper."""
    def __init__(self, execute, configuration):
        super(VFSHelper, self).__init__(execute, configuration)
        self._execute = execute
        self.DINGO_TOOL_PATH = 'dingo'
        self.fs_name = self.configuration.dingofs_fs_name
        self.fs_mount_point_base = self.configuration.fs_mount_point_base

    def _get_options_not_allowed(self):
        """Get access options that are not allowed in extra-specs."""
        return ['access_type=ro', 'access_type=rw']

    def get_access_option(self, access):
        """Get access option string based on access level."""
        if access['access_level'] == constants.ACCESS_LEVEL_RO:
            return 'Access_Type=RO'
        else:
            return 'Access_Type=RW'

    def remove_export(self, share_path, share):
        """Remove export for the given share path."""
        if not self.configuration.dingofs_enable_export:
            LOG.debug('dingofs_enable_export is disabled, skipping '
                      '"dingo export remove" for share %s.', share['name'])
            return
        try:
            out, __ = self._execute(self.DINGO_TOOL_PATH, 'export', 'remove',
                                   '--nfs.path', share_path)

        except exception.ProcessExecutionError as e:
            msg = (_('Failed to delete DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)

    def allow_access(self, local_path, share, access):
        """Allow access to the host."""

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(reason='Only ip access type '
                                                      'supported.')
        if not self.configuration.dingofs_enable_export:
            LOG.debug('dingofs_enable_export is disabled, skipping '
                      '"dingo export add" for share %s.', share['name'])
            return
        #check has export?
        #add access
        try:
            local_path = '%s/%s' % (self.fs_mount_point_base, share['name'])
            export_opts = self.get_export_options(share, access, 'VFS')
            out, __ = self._execute(self.DINGO_TOOL_PATH, 'export', 'add',
                                   '--nfs.path', local_path, '--nfs.conf', export_opts)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to add DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)
        


    def deny_access(self, local_path, share, access):
        """Deny access to the host."""
        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(reason='Only ip access type '
                                                      'supported.')
        if not self.configuration.dingofs_enable_export:
            LOG.debug('dingofs_enable_export is disabled, skipping '
                      '"dingo export remove" for share %s.', share['name'])
            return
        #remove access
        try:
            export_opts = self.get_export_options(share, access, 'VFS')
            out, __ = self._execute(self.DINGO_TOOL_PATH, 'export', 'remove',
                                   '--nfs.path', local_path, '--nfs.conf', export_opts)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to remove DingoFS share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.DingoFSException(msg)

    def resync_access(self, local_path, share, access_rules):
        pass
