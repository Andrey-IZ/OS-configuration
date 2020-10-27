#!/usr/bin/env python
# coding=utf-8
# PYTHON_ARGCOMPLETE_OK

import sys, shlex
import subprocess, pty, os
import errno
import logging

__author__ = 'andrew@mail.ru'
__date__ = "09.01.2018"
__license__ = "GPL"
import time
__version__ = "0.4.0"

PREFIX = ' -- '
USER_NAME = 'user'
USER_PASSWD = 'password'
NETUSER_PASSWD = 'net_apssword'
ROOT_PASSWD = ''

FTP_SERVER = 'ftp://2211.grad.rnd/repo/zarya158-02/'
PACKET_MGR = 'yum'

EXEC_FORMAT = '===============\n   {{{0}}} # {1} {2} \n==============='

# ==========  SYSTEM FUNCTIONS  ============
def run_simple(cmd, input_list=None, path=None):
    """

    :param cmd:
    :param input_list:
    :param path:
    :return: success
    """
    if path is None:
        path = '/home/' + os.getlogin()

    if not input_list:
        input_list = list('')

    p = subprocess.Popen(cmd, cwd=path, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    log.info(EXEC_FORMAT.format(path, cmd, input_list if input_list else ''))
    output = p.communicate(input=str('\n').join(input_list))

    log.info(output[0].decode(sys.getfilesystemencoding()))
    if output[1]:
        log.critical('Errors:\n' + output[1].decode(sys.getfilesystemencoding()))
    return p.returncode == 0


def run_inter(cmd, input_list=None, path=None):
    import subprocess, pty, os

    if path is None:
        path = '/home/' + os.getlogin()

    if not input_list:
        input_list = list('')

    output = list()
    master, slave = pty.openpty()

    log.info(EXEC_FORMAT.format(path, cmd, input_list if input_list else ''))

    # stderr напраляем также в pty!
    process = subprocess.Popen(cmd, shell=True, cwd=path,
                               stdout=slave, stderr=subprocess.STDOUT, stdin=slave)
    # закрываем вспомогательный дескриптор! иначе зависнет в ожидании ввода
    os.close(slave)

    def _reader(fd, list_input_args):
        try:
            input_arg_iter = list_input_args.__iter__()
            while True:
                import os
                buffer = os.read(fd, 1024)
                try:
                    input_arg = input_arg_iter.next()
                    os.write(fd, input_arg + '\n')
                except StopIteration:
                    pass
                if not buffer:
                    return

                output.append(buffer)
                yield buffer

        except (IOError, OSError) as e:
            pass

    # считываем по кусочку
    for block in _reader(master, input_list):
        # и записываем их в стандартный поток
        os.write(1, block)

    proc_status = process.wait()
    log.info(''.join(output).decode(sys.getfilesystemencoding()))
    log.debug('-- status = {0}\n'.format(proc_status))

    if proc_status:
        log.critical('Errors: proc= {0}'.format(proc_status))
    return proc_status == 0


# def run_easy(cmd, input_list=None, path=None):
#     if path is None:
#         path = '/home/' + os.getlogin()
#
#     if not input_list:
#         input_list = list('')
#
#     p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=path,
#                      stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)
#     log.info(EXEC_FORMAT.format(path, cmd, input_list if input_list else ''))
#
#     if input_list:
#         p.stdin.write(str('\n').join(input_list))
#
#     while p.poll() is None:
#         line = p.stdout.readline()
#         if not line:
#             # p.stdin.write(str('\n').join(input_list))
#             break
#         print line.replace('\n', '')
#     p.wait()


run = run_simple


def init_args():
    """
    Gets dictionary arguments of command line
    :return: dict args
    """
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    description = 'Configurator OS Zarya with prescriptions for a properly job of applications.\nif no options were given\
     then it will be installed all applications'
    epilog = '''(c) Andrew 2018. Copyright and Related Rights Regulations (zarya_configurator) 2018 No. 2'''
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            description=description, epilog=epilog)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='show the process in details')
    parser.add_argument('-vv', '--very-verbose', dest='very_verbose', action='store_true',
                        help='show the process in details for debugging')
    parser.add_argument('-nr', '--no-remote', dest='no_remote', action='store_true',
                        help='ignores installing the vnc and ssh servers')
    parser.add_argument('-se', '--turn-off-selinux', dest='turn_off_selinux', action='store_true',
                        help='turns off the SElinux')
    parser.add_argument('-su', '--sudo-user', dest='sudo', action='store_true', help='allow sudo access modificator')
    parser.add_argument('-d', '--dev-tools', dest='dev_tools', action='store_true',
                        help='installs only development dependencies')
    parser.add_argument('-r', '--remote', dest='remote', action='store_true')
    parser.add_argument('-sr', '--setup-repos', dest='setup_repos',
                        help='Sets the path to repository')
    parser.add_argument('-pg', '--setup-postgres', dest='setup_postgres', action='store_true',
                        help='Setup the postgresql database')

    args = sys.argv[1:]
    # if not args:
    #     args = shlex.split('-u -d -r')
    args = parser.parse_args(args)
    args = vars(args)

    mode = logging.WARNING
    global run
    if args.get('verbose', False):
        mode = logging.INFO
        run = run_simple
        del args['verbose']
    if args.get('very_verbose', False):
        mode = logging.DEBUG
        run = run_inter
        del args['very_verbose']

    global log
    log = init_log(mode)
    return args


def init_log(mode):
    log = logging.Logger('Installer')

    file_handler = logging.FileHandler(os.getcwd() + '/log.txt', encoding=sys.getfilesystemencoding(), mode='w')
    file_handler.setFormatter(logging.Formatter(u'%(asctime)-15s [LINE:%(lineno)d] <%(levelname)s> \
    %(message)s'))
    file_handler.setLevel(logging.DEBUG)
    log.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(u'%(message)s'))
    console_handler.setLevel(mode)
    log.addHandler(console_handler)
    print('LOG mode = ' + logging.getLevelName(mode))
    return log


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python > 2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def run_behalf_of_user(cmd, user_name, user_passwd, input_list=None, path=None):
    cmd = 'su {0} -c "{1}"'.format(user_name, cmd)
    if not run(cmd, input_list=input_list, path=path):
        log.critical('Failure. It hasn\'t started behalf of user')
        return False
    return True


def install_apps(args):
    """
    Installs all applications by order that's given in APPS tuple
    :param args: it's dictionary of arguments
    :return:
    """
    def f(arg):
        k, v = arg
        if isinstance(k, str) and str(k).startswith('no_'):
            return False
        return v
    arg_check = list(filter(f, args.items()))
    is_install_all = False
    if not arg_check:
        is_install_all = True
        log.warning('Setting up all configs: ' + str(is_install_all))

    try:
        for k, func in TOOLS_CHAIN:
            if is_install_all or args.get(k, False):
                if not args.get('no_' + k, False):
                    print(k, func, is_install_all)
                    if not func(args.get(k)):
                        raise ValueError('Configuring was aborted')
    except ValueError as e:
        log.critical('-- ERROR: ' + e.args[0])


# ################## Configuration  OS #######################


def turn_off_selinux(arg):
    log.warning('Turning selinux off ...')

    config = '/etc/selinux/config'

    import fileinput, re
    exception_dict = {'SELINUX': 'disabled', 'SELINUXTYPE': 'targeted'}

    def replace_func(m):
        key = m.group('key')
        opt = exception_dict.get(key)
        return "{0}={1}".format(key, opt)

    isBad = True
    r = re.compile(
        r"^\s*(?P<key>{0})\s*=\s*(?P<option>\w+).*$".format('|'.join([re.escape(s) for s in exception_dict.keys()])))
    for line in fileinput.input(files=config, inplace=True, backup='.orig'):
        s = ''
        if line and not line == '\n':
            s = r.sub(repl=replace_func, string=line)
            isBad = False
        print(s[:-1])

    if isBad:
        raise Exception('Config file hasn\'t been changed')

    log.warning('OK')
    log.warning('==============\n --- Now you should restart the machine !! \n============== ')
    return True


def install_vnc_server(arg):
    log.warning(PREFIX + 'Installing vnc-server ...')
    if not run('sudo {0} install vnc-server'.format(PACKET_MGR), ['y']):
        log.critical('Failure')
        return False

    # run('useradd netuser')
    # run('passwd netuser')

    def set_vnc_config():
        log.warning(PREFIX + 'set vnc server config..')
        vnc_server_config_path = '/etc/sysconfig/vncservers'
        vncservers_file = '''
        #The Config for Zarya
        VNCSERVERS="1:{0}"
        VNCSERVERARGS[1]="-geometry 1024x800"
        '''.format(USER_NAME)
        import fileinput, re
        r = re.compile(r'^([^#].*)$')
        for line in fileinput.input(files=vnc_server_config_path, inplace=True, backup='.orig'):
            s = ''
            if line and not line == '\n':
                s = r.sub(r"# \1", line)
            print(s[:-1])
        with open(vnc_server_config_path, 'at') as fd:
            for line in vncservers_file.splitlines():
                fd.write(line.lstrip() + '\n')
        log.warning(PREFIX + 'OK')

    def set_user_vnc_passwd():
        log.warning(PREFIX + 'set vnc passwd ...')
        if not run_behalf_of_user('vncpasswd', user_name=USER_NAME, user_passwd=USER_PASSWD,
                                  input_list=[NETUSER_PASSWD, NETUSER_PASSWD], path='/home/' + USER_NAME):
            log.critical('Failure. It hasn\'t passed netuser password')
            raise Exception()
        if not os.path.exists('/home/{0}/.vnc/passwd'.format(USER_NAME)):
            raise Exception('Vnc passwd was not created')
        log.warning(PREFIX + 'OK')

    def try_to_stop_vnc_server():
        log.warning(PREFIX + 'Stopping vnc server ...')
        if not run('/etc/init.d/vncserver stop'):
            log.warning('Failure. Vncserver hasn\'t been stopped')
        log.warning(PREFIX + 'OK')
        pass

    def try_to_start_vnc_server():
        log.warning(PREFIX + 'Starting vnc server ...')
        if not run('/etc/init.d/vncserver start'):
            log.critical('Failure. Vncserver hasn\'t been started')
            raise Exception()
        log.warning(PREFIX + 'OK')

    def set_vnc_environment():
        log.warning(PREFIX + 'Setting up vnc environment ...')
        vnc_xstartup_file = """
        #!/bin/sh
        [ -r /etc/sysconfig/i18n ] && . /etc/sysconfig/i18n
        export LANG
        export SYSFONT
        vncconfig -iconic &
        unset SESSION_MANAGER
        unset DBUS_SESSION_BUS_ADDRESS

        echo "launching xinitrc ..."

        [ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
        xsetroot -solid grey
        
        echo "start x ..."
        startxfce4 &
        terminator &
        """

        log.warning('write xstartup file ...')
        with open('/home/{0}/.vnc/xstartup'.format(USER_NAME), 'w') as fd:
            for line in vnc_xstartup_file.lstrip().splitlines():
                fd.write(line.lstrip() + '\n')

            log.warning(PREFIX + 'OK')

    def set_vnc_server_at_startup():
        log.warning(PREFIX + 'start vnc service at startup ...')
        if not run('chkconfig --level 35 vncserver on'):
            raise Exception()
        log.warning(PREFIX + 'OK')

    def set_firewall_rules():
        log.warning(PREFIX + 'add new rules into firewall ...')
        run('/etc/init.d/iptables stop')
        iptables_rules_conf = '/etc/sysconfig/iptables'

        iptables_rules = '''
        -A INPUT -m state --state NEW -m tcp -p tcp --dport 5801  -j ACCEPT
        -A INPUT -m state --state NEW -m tcp -p tcp --dport 5901 -j ACCEPT
        -A INPUT -m state --state NEW -m tcp -p tcp --dport 6001  -j ACCEPT

        # ftp server
        -A INPUT -p tcp -m multiport --destination-port 20,21,50000:50400 -j ACCEPT

        # NetBIOS name service
        -A INPUT -p udp --dport 137:138  -j ACCEPT
        # SMB TCP conversation
        -A INPUT -p udp --dport 32800:32900 -j ACCEPT
        # NetBIOS-SSN
        -A INPUT -p tcp --dport 139  -j ACCEPT
        # Microsoft-DS
        -A INPUT -p tcp --dport 445  -j ACCEPT
            '''
        log.info(PREFIX + 'accepting rules for the firewall...')

        def get_repl_str():
            return '\n'.join([row.lstrip() for row in iptables_rules.splitlines()])

        def replace_rules(config):
            log.warning(PREFIX + 'adding config rules ...')
            import fileinput, re
            r = re.compile(r'^(\s*COMMIT\s*)$')
            for line in fileinput.input(files=config, inplace=True, backup='.orig'):
                if line and not line == '\n':
                    if line.find('reject') > 0:
                        line = ''
                    else:
                        line = r.sub(r"{0}\n\1".format(get_repl_str()), line)
                print(line[:-1])
            log.warning(PREFIX + 'OK')

        def change_file(conf):
            log.warning(PREFIX + 'replacing config rules ...')
            begin_rules='''
            *filter
            :INPUT ACCEPT [0:0]
            :FORWARD ACCEPT [0:0]
            :OUTPUT ACCEPT [0:0]
            -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            -A INPUT -p icmp -j ACCEPT
            -A INPUT -i lo -j ACCEPT
            -A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
            '''
            with open(conf, 'w') as fd:
                for line in begin_rules.lstrip().splitlines():
                    fd.write(line.lstrip() + '\n')

            with open(conf, 'a') as fd:
                for line in iptables_rules.lstrip().splitlines():
                    fd.write(line.lstrip() + '\n')

            with open(conf, 'a') as fd:
                fd.writelines(['COMMIT'])
            log.warning(PREFIX + 'OK')

        def check_config(conf):
            with open(conf, 'r') as fd:
                for line in fd.readlines():
                    if line.find('#') > 0 and len(line) > 1:
                        return False
            return True

        if check_config(iptables_rules_conf):
            replace_rules(iptables_rules_conf)
        else:
            change_file(iptables_rules)

        if not run('/etc/init.d/iptables start'):
            log.critical('Failure. The firewall rules was not accepted')
            raise Exception()
        log.warning(PREFIX + 'OK')

    def restart_vnc_server():
        log.warning(PREFIX + 'restarting vnc service ...')
        try_to_stop_vnc_server()
        try_to_start_vnc_server()

    try:
        set_vnc_config()
        try_to_stop_vnc_server()
        set_user_vnc_passwd()
        try_to_start_vnc_server()
        set_vnc_environment()
        set_vnc_server_at_startup()
        set_firewall_rules()
        restart_vnc_server()
    except:
        log.critical('Vnc server has not been installed')
        return False

    return True


def install_ssh_server(arg):
    log.warning('- Installing ssh-server ...')
    app = 'openssh-server.x86_64'
    if not run(cmd='{0} install {1}'.format(PACKET_MGR, app), input_list=['y']):
        log.critical('Failure')
        return False

    def replace_prop(config, r, replace_func):
        for line in fileinput.input(files=config, inplace=True, backup='.orig'):
            if line and not line == '\n':
                line = r.sub(repl=replace_func, string=line)
            print(line[:-1])

    import fileinput, re

    # ---------- sshd ----------
    config = '/etc/ssh/sshd_config'
    exception_dict = {'AllowAgentForwarding': 'yes',
                      'AllowTcpForwarding': 'yes',
                      'X11Forwarding': 'yes',
                      'X11DisplayOffset': '10',
                      'X11UseLocalhost': 'yes',
                      'TCPKeepAlive': 'yes',
                      'UsePAM': 'no',
                      }
    r = re.compile(
        r"^[#]?\s*(?P<key>{0})\s+(?P<option>\w+).*$".format('|'.join([re.escape(s) for s in exception_dict.keys()])), re.I)

    def replace_func(m):
        key = m.group('key')
        opt = exception_dict.get(key)
        return "{0} {1}".format(key, opt)

    replace_prop(config, r, replace_func)

    # ----- ssh  -----------
    config2 = '/etc/ssh/ssh_config'
    exception_dict2 = {'ForwardX11': 'yes',
                       'ForwardX11Trusted': 'yes'
                       }
    r2 = re.compile(
        r"^[#]?\s*(?P<key>{0})\s+(?P<option>\w+).*$".format('|'.join([re.escape(s) for s in exception_dict2.keys()])),
        re.I)


    def replace_func2(m):
        key = m.group('key')
        opt = exception_dict2.get(key)
        return "{0} {1}".format(key, opt)

    replace_prop(config2, r2, replace_func2)

    if not run('sudo service sshd restart'):
        log.critical('Failure')
        return False

    log.warning('- OK')
    return True


def install_remote_control(arg):
    log.warning('Installing remote control tools ...')
    if install_vnc_server(arg) and install_ssh_server(arg):
        log.warning('OK')
        return True
    log.critical('Failure')
    return False


def install_dev_tools(arg):
    log.warning('Installing dev-tools ...')
    tools = ('gcc', 'gcc-c++', 'qt-devel', 'git', 'kernel-devel.x86_64', 'libusb1-devel', 
             'mc', 'cmake', 'doxygen.x86_64', 'rpm-build.x86_64', 'zarya-lsb.x86_64', 'expect.x86_64')
    for app in tools:
        if not run(cmd='{0} install {1}'.format(PACKET_MGR, app), input_list=['y']):
            log.critical(PREFIX + 'Installing {0}:  Failure'.format(app))
            return False
        else:
            log.warning(PREFIX + 'Installing {0}: OK'.format(app))

    log.warning('OK')
    return True


def turn_off_poly_instantiation(arg):
    log.warning('Turning off poly_instantiation ...')

    namespace_conf = '/etc/security/namespace.conf'
    import fileinput, re

    exception_list = ('/tmp', '/var/tmp', '/home/$USER')
    r = re.compile(r'^\s?(({0})\s.*)'.format('|'.join([re.escape(s) for s in exception_list])))
    for line in fileinput.input(files=namespace_conf, inplace=True, backup='.orig'):
        s = ''
        if line and not line == '\n':
            s = r.sub(r"# \1", line)
        print(s[:-1])

    if not os.path.exists(namespace_conf):
        log.critical('Failed')
        return False
    log.warning('OK')
    return True


def remove_zarya_tests(arg):
    log.warning('Removing zarya-tests ...')
    if run(cmd='{0} remove zarya-tests'.format(PACKET_MGR), input_list=['y']):
        log.warning('OK')
        return True
    log.warning('Failure')
    return False


def setup_sudo(arg):
    """
    :param arg:
    :return:
    """
    log.warning('Settting up sudo modificator ...')
    conf = '/etc/sudoers'

    if not run('chmod +w {0}'.format(conf)):
        log.critical('Failure. File {0} doesn\'t access')
        return False

    import fileinput, re
    r = re.compile(r'^([^#].*)$')
    isGood = False
    for line in fileinput.input(files=conf, inplace=True, backup='.orig'):
        if re.match(r'root\s+ALL=\(ALL\)\s+ALL' , line):
            line += '{0}\tALL=(ALL)\tALL\n'.format(USER_NAME)
            isGood = True
        print(line[:-1])

    if not isGood:
        log.critical('Failure')
        return False

    run('chmod u=r {0}'.format(conf))
    log.warning(PREFIX + 'OK')
    return True


def setup_repos(params):
    """
    Sets up the repositories on the Zarya OS
    :return:
    """
    base_iso = os.path.realpath('.') + '/Zarya158-02-x86_64-2016.03.01-DVD.iso'
    devtools_iso = os.path.realpath('.') + '/DevTools-099-01-x86_64-2016.03.01-DVD.iso'
    base_ftp = FTP_SERVER + '/base'
    devtools_ftp = FTP_SERVER + '/dev_tools'

    base_mnt = '/mnt/repo/base'
    mkdir_p(base_mnt)
    if os.path.exists(base_iso):
        run('mount -o loop {0} {1}'.format(base_iso, base_mnt))
    base_mnt = 'file://' + base_mnt

    devtools_mnt = '/mnt/repo/devtools'
    mkdir_p(devtools_mnt)
    if os.path.exists(devtools_iso):
        run('mount -o loop {0} {1}'.format(devtools_iso, devtools_mnt))
    devtools_mnt = 'file://' + devtools_mnt  
    
    repo1_path_os = '/etc/{0}.repos.d/{1}.repo'
    repo1_description = '''
    [Zarya{1}]
    name=Zarya158-02 {1}
    baseurl={0}
    metadata_expire=-1
    gpgcheck=0
    cost=500
    skip_if_unavailable=True
    enabled=1
    '''

    repo2_path_os = '/etc/{0}.repos.d/{1}.repo'
    repo2_description = '''
    [Zarya{1}]
    name=Zarya158-02 {1}
    baseurl={0}
    metadata_expire=-1
    gpgcheck=0
    cost=500
    skip_if_unavailable=True
    enabled=1
    '''

    log.warning('Setting up the repositories on the Zarya OS...')
    
    def fill_repodata(repo_path_os, repo_description):
        mkdir_p(os.path.dirname(repo_path_os))
        with open(repo_path_os, 'w') as fd:
            for line in repo_description.lstrip().splitlines():
                fd.write(line.lstrip() + '\n')

    fill_repodata(repo1_path_os.format(PACKET_MGR, 'base_iso'), repo1_description.format(base_mnt, 'BaseISO'))
    fill_repodata(repo2_path_os.format(PACKET_MGR, 'devtools_iso'), repo2_description.format(devtools_mnt, 'DevISO'))
    fill_repodata(repo1_path_os.format(PACKET_MGR, 'base_ftp'), repo1_description.format(base_ftp, 'BaseFTP'))
    fill_repodata(repo2_path_os.format(PACKET_MGR, 'devtools_ftp'), repo2_description.format(devtools_ftp, 'DevFTP'))

    run('{0} clean all'.format(PACKET_MGR))
    if not run('{0} update'.format(PACKET_MGR)):
        log.critical('Failed')
        return False
    log.warning('OK')
    return True


def setup_postgres(packets_paths='.'):
    log.warning('Setting up the postgres DB...')
    postgres_name='postgresql-12'
    rpmlist = ['postgresql12-libs-12.3-1PGDG.rhel6.x86_64.rpm',
               'postgresql12-12.3-1PGDG.rhel6.x86_64.rpm', 
               'postgresql12-server-12.3-1PGDG.rhel6.x86_64.rpm',
               'postgresql12-plpython-12.3-1PGDG.rhel6.x86_64.rpm'
               ]

    for rpm in rpmlist:
        run('rpm -iUvh {0}/{1}'.format(os.path.realpath('.'), rpm))
        
    run('service postgresql-12 initdb', input_list=[USER_PASSWD])
    run('chkconfig {0} on'.format(postgres_name))
    run('service {0} start'.format(postgres_name), input_list=[USER_PASSWD])

    enter_passw_script = '''#!/usr/bin/expect -f

set timeout -1
spawn sudo -u postgres psql postgres
expect -exact "psql (12.3)\r
Введите \"help\", чтобы получить справку.\r
\r
postgres=# "
send -- "\\password postgres\r"
expect -exact "\\password postgres\r
Введите новый пароль: "
send -- "{0}\r"
expect -exact "\r
Повторите его: "
send -- "{0}\r"
expect -exact "\r
postgres=# "
send -- ""
expect eof
    '''.format(USER_PASSWD)

    # with open('script.exp', 'w') as f:
    #     f.writelines(enter_passw_script)
    run('/usr/bin/expect script.exp', path=os.path.realpath('.'))
        # input_list=["\\password postgres\n\r", "2412\n\r", "2412\n\r", "\\q\r\n"])


    print('---exits----')
    return True



TOOLS_CHAIN = (
    ('setup_repos', setup_repos),
    ('turn_off_selinux', turn_off_selinux),
    ('rem_poly_instantiation', turn_off_poly_instantiation),
    ('rem_zarya_tests', remove_zarya_tests),
    ('dev_tools', install_dev_tools),
    ('sudo', setup_sudo),
    ('remote', install_remote_control),
    ('setup_postgres', setup_postgres),
)

if __name__ == '__main__':
    print('ver = {0}'.format(__version__))
    # log = init_log(logging.INFO)
    install_apps(init_args())
    # run('sudo -u user ls')
    # os.chdir('/home/andrew/projects/sys_install/')
    # run ('top', [''])
    # init_vnc_server()
    # run('sudo vnc-server', ['y'])
    # run('ls -l', ['q'])
    # run('ping 192.22.11.24')
    # setup_repos('/home/')
