"""The version manager against a fake root folder (no root, no packages, no systemd needed).
A fake install.sh writes the kind of files the real one does, under HG_ROOT."""
import importlib.util
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
MANAGER = os.path.join(HERE, '..', 'src', 'host_guard', 'manager.py')

FAKE_INSTALL = r'''#!/bin/bash
set -e
R="$HG_ROOT"; V="$(cat "$(dirname "$0")/../VERSION")"
mkdir -p "$R/etc/ssh/sshd_config.d" "$R/usr/local/sbin" "$R/etc/systemd/system/timers.target.wants" \
  "$R/etc/sysctl.d" "$R/etc/host-guard"
echo "policy $V" > "$R/etc/ssh/sshd_config.d/01-host-guard.conf"
printf '#!/bin/sh\necho engine %s\n' "$V" > "$R/usr/local/sbin/hostguard"; chmod 755 "$R/usr/local/sbin/hostguard"
echo "[Timer] $V" > "$R/etc/systemd/system/host-guard-health.timer"
ln -sfn ../host-guard-health.timer "$R/etc/systemd/system/timers.target.wants/host-guard-health.timer"
echo "net.x = $V" > "$R/etc/sysctl.d/99-host-guard.conf"
echo "mail $V" > "$R/etc/msmtprc"
[ -f "$R/etc/host-guard/guard.conf" ] || printf 'MAIL_TO=%s\nLOGIN_USER=%s\n' "$MAILTO" "$LOGIN" > "$R/etc/host-guard/guard.conf"
echo "$*" > "$R/etc/host-guard/last-args"
if [ "$V" = 0.3.1 ] && [ -n "${EXTRA:-}" ]; then echo extra > "$R/etc/sysctl.d/98-extra.conf"; fi
[ -z "${FAIL_INSTALL:-}" ] || exit 3
'''


def make_payload(base, version):
    d = base / f'payload-{version}'
    (d / 'guard').mkdir(parents=True)
    (d / 'panel').mkdir()
    (d / 'examples' / 'profiles').mkdir(parents=True)
    (d / 'VERSION').write_text(version + '\n')
    (d / 'guard' / 'install.sh').write_text(FAKE_INSTALL)
    (d / 'panel' / 'install.sh').write_text('#!/bin/bash\nmkdir -p "$HG_ROOT/etc/host-guard-panel"\n'
                                            'echo "PORT=$2" > "$HG_ROOT/etc/host-guard-panel/panel.conf"\n')
    (d / 'examples' / 'profiles' / 'plain-vps.conf').write_text('BACKUP_CMD=tar -cf - /etc\n')
    return str(d)


@pytest.fixture
def hg(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    (root / 'etc').mkdir(parents=True)
    (root / 'etc' / 'msmtprc').write_text('the admin mail setup from before\n')
    os.chmod(root / 'etc' / 'msmtprc', 0o600)
    monkeypatch.setenv('HG_ROOT', str(root))
    monkeypatch.setenv('MAILTO', 'a@example.com')
    monkeypatch.setenv('LOGIN', 'ops')
    monkeypatch.delenv('SUDO_USER', raising=False)
    spec = importlib.util.spec_from_file_location('hgmanager', MANAGER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    calls = []

    def fake_run(cmd, **kw):
        if cmd[0] == 'bash':
            kw.pop('env', None)
            return subprocess.run(cmd, check=False).returncode
        calls.append(cmd)
        return 0
    monkeypatch.setattr(m, 'run', fake_run)
    m.calls = calls
    m.root = root
    m.p = {v: make_payload(tmp_path, v) for v in ('0.3.0', '0.3.1', '0.2.9')}

    def use(version):
        monkeypatch.setenv('HG_PAYLOAD', m.p[version])
    m.use = use
    return m


def read(m, p):
    return (m.root / p.lstrip('/')).read_text()


def state(m):
    return json.loads((m.root / 'opt' / 'host-guard' / 'state.json').read_text())


def install(m, version, *args):
    m.use(version)
    return m.main(['install', *args])


def test_versions_compare_as_numbers():
    spec = importlib.util.spec_from_file_location('hgm', MANAGER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.parse_version('0.10.0') > m.parse_version('0.9.9')
    assert m.parse_version('v1.2.3') == (1, 2, 3)
    assert m.parse_version('junk') == (-1,)


def test_first_install_records_every_change(hg):
    assert install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops') == 0
    assert state(hg)['version'] == '0.3.0'
    assert os.readlink(hg.root / 'opt/host-guard/current') == 'releases/0.3.0'
    (folder,) = (hg.root / 'opt/host-guard/history').iterdir()
    man = json.loads((folder / 'manifest.json').read_text())
    paths = {c['path'] for c in man['changes']}
    assert {'/etc/ssh/sshd_config.d/01-host-guard.conf', '/usr/local/sbin/hostguard', '/etc/msmtprc',
            '/etc/systemd/system/host-guard-health.timer',
            '/etc/systemd/system/timers.target.wants/host-guard-health.timer'} <= paths
    assert '/usr/local/sbin/host-guard' not in paths           # the manager is never rolled back
    assert (folder / 'files/etc/msmtprc').read_text() == 'the admin mail setup from before\n'
    assert not (folder / 'files/usr/local/sbin/hostguard').exists()   # it did not exist before: nothing to copy
    assert man['status'] == 'ok' and man['action'] == 'install'
    assert (hg.root / 'usr/local/sbin/host-guard').exists()
    assert 'tests' not in os.listdir(hg.root / 'opt/host-guard/releases/0.3.0/guard')


def test_first_install_needs_recipients(hg):
    assert install(hg, '0.3.0') == 1
    assert not (hg.root / 'etc/ssh').exists()


def test_unknown_option_stops_before_anything_changes(hg):
    assert install(hg, '0.3.0', '--mail-to', 'a@example.com', '--mial-from', 'x') == 1
    assert not (hg.root / 'opt/host-guard/history').exists()


def test_upgrade_then_rollback_restores_byte_for_byte(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    v030 = {p: read(hg, p) for p in ('/etc/ssh/sshd_config.d/01-host-guard.conf', '/etc/msmtprc',
                                      '/etc/sysctl.d/99-host-guard.conf')}
    hg.use('0.3.1')
    os.environ['EXTRA'] = '1'
    try:
        assert hg.main(['upgrade']) == 0
    finally:
        del os.environ['EXTRA']
    assert state(hg)['version'] == '0.3.1'
    assert read(hg, '/etc/msmtprc') == 'mail 0.3.1\n'
    assert '--login-user ops' in read(hg, '/etc/host-guard/last-args')   # the saved option came back
    assert hg.main(['rollback', '--yes']) == 0
    assert state(hg)['version'] == '0.3.0'
    assert {p: read(hg, p) for p in v030} == v030
    assert not (hg.root / 'etc/sysctl.d/98-extra.conf').exists()          # a file 0.3.1 added is gone
    assert os.readlink(hg.root / 'opt/host-guard/current') == 'releases/0.3.0'
    assert ['sysctl', '--system'] in hg.calls and ['systemctl', 'daemon-reload'] in hg.calls


def test_rollback_keeps_a_file_an_admin_changed(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.1')
    hg.main(['upgrade'])
    (hg.root / 'etc/sysctl.d/99-host-guard.conf').write_text('tuned by hand\n')
    assert hg.main(['rollback', '--yes']) == 0
    assert read(hg, '/etc/sysctl.d/99-host-guard.conf') == 'tuned by hand\n'
    assert read(hg, '/etc/msmtprc') == 'mail 0.3.0\n'


def test_rollback_force_restores_it_anyway(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.1')
    hg.main(['upgrade'])
    (hg.root / 'etc/sysctl.d/99-host-guard.conf').write_text('tuned by hand\n')
    assert hg.main(['rollback', '--yes', '--force']) == 0
    assert read(hg, '/etc/sysctl.d/99-host-guard.conf') == 'net.x = 0.3.0\n'


def test_rollback_without_a_terminal_needs_yes(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert hg.main(['rollback']) == 1
    assert state(hg)['version'] == '0.3.1'


def test_rollback_to_a_version_several_steps_back(hg):
    install(hg, '0.2.9', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.0')
    hg.main(['upgrade'])
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert hg.main(['rollback', '--to', '9.9.9', '--yes']) == 1
    assert hg.main(['rollback', '--to', '0.2.9', '--yes']) == 0
    assert state(hg)['version'] == '0.2.9'
    assert read(hg, '/etc/msmtprc') == 'mail 0.2.9\n'
    assert hg.main(['rollback', '--yes']) == 1                    # only uninstall goes further


def test_a_failed_install_is_undone_at_once(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    before = {p: read(hg, p) for p in ('/etc/msmtprc', '/etc/sysctl.d/99-host-guard.conf')}
    os.environ['FAIL_INSTALL'] = '1'
    try:
        hg.use('0.3.1')
        assert hg.main(['upgrade']) == 1
    finally:
        del os.environ['FAIL_INSTALL']
    assert {p: read(hg, p) for p in before} == before
    assert state(hg)['version'] == '0.3.0'
    failed = [json.loads((d / 'manifest.json').read_text()) for d in (hg.root / 'opt/host-guard/history').iterdir()]
    assert [m['status'] for m in sorted(failed, key=lambda m: m['id'])] == ['ok', 'failed']


def test_an_older_version_asks_first(hg):
    install(hg, '0.3.1', '--mail-to', 'a@example.com', '--login-user', 'ops')
    assert install(hg, '0.3.0') == 1                               # no terminal, no flag: refused
    assert state(hg)['version'] == '0.3.1' and read(hg, '/etc/msmtprc') == 'mail 0.3.1\n'
    assert install(hg, '0.3.0', '--allow-downgrade') == 0
    assert state(hg)['version'] == '0.3.0'


def test_the_same_version_again_is_a_repair(hg, capsys):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    (hg.root / 'usr/local/sbin/hostguard').write_text('broken')
    assert install(hg, '0.3.0') == 0
    assert 'repair' in capsys.readouterr().out
    assert 'engine 0.3.0' in read(hg, '/usr/local/sbin/hostguard')


def test_recipients_come_from_guard_conf_not_the_saved_options(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    conf = hg.root / 'etc/host-guard/guard.conf'
    conf.write_text('MAIL_TO=a@example.com,b@example.com\nLOGIN_USER=ops\n')   # as the panel would change it
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert '--mail-to a@example.com,b@example.com' in read(hg, '/etc/host-guard/last-args')
    assert '--mail-to' not in json.dumps(state(hg)['options'])


def test_profiles_are_saved_relative_to_the_release(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops',
            '--profile', 'examples/profiles/plain-vps.conf')
    assert state(hg)['options']['--profile'] == 'examples/profiles/plain-vps.conf'
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert 'releases/0.3.1/examples/profiles/plain-vps.conf' in read(hg, '/etc/host-guard/last-args')


def test_the_panel_is_installed_and_remembered(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops', '--with-panel', '--panel-port', '8700')
    assert read(hg, '/etc/host-guard-panel/panel.conf') == 'PORT=8700\n'
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert state(hg)['with_panel'] is True and state(hg)['panel_port'] == '8700'


def test_new_files_from_packages_are_left_to_dpkg(hg, monkeypatch):
    monkeypatch.setattr(hg, 'dpkg_owned', lambda paths: {p for p in paths if p.endswith('99-host-guard.conf')})
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    (folder,) = (hg.root / 'opt/host-guard/history').iterdir()
    paths = {c['path'] for c in json.loads((folder / 'manifest.json').read_text())['changes']}
    assert '/etc/sysctl.d/99-host-guard.conf' not in paths


def test_a_failed_check_reverts_the_rollback(hg, monkeypatch):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.1')
    hg.main(['upgrade'])
    monkeypatch.setattr(hg, 'checks', lambda paths: ['sshd -t rejected the SSH settings'])
    assert hg.main(['rollback', '--yes']) == 1
    assert state(hg)['version'] == '0.3.1'
    assert read(hg, '/etc/ssh/sshd_config.d/01-host-guard.conf') == 'policy 0.3.1\n'
    assert read(hg, '/etc/msmtprc') == 'mail 0.3.1\n'


def test_uninstall_puts_the_server_back(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    hg.use('0.3.1')
    hg.main(['upgrade'])
    assert hg.main(['uninstall', '--yes']) == 0
    assert read(hg, '/etc/msmtprc') == 'the admin mail setup from before\n'
    assert oct(os.stat(hg.root / 'etc/msmtprc').st_mode & 0o777) == '0o600'
    for p in ('usr/local/sbin/hostguard', 'usr/local/sbin/host-guard', 'etc/ssh/sshd_config.d/01-host-guard.conf',
              'etc/systemd/system/host-guard-health.timer', 'etc/systemd/system/timers.target.wants/host-guard-health.timer',
              'opt/host-guard/releases', 'opt/host-guard/state.json'):
        assert not os.path.lexists(hg.root / p), p
    assert (hg.root / 'etc/host-guard/guard.conf').exists()                   # settings kept without --purge
    assert (hg.root / 'opt/host-guard/history').exists()
    assert ['systemctl', 'stop', 'host-guard-health.timer'] in hg.calls


def test_purge_will_not_strand_the_backups(hg):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    (hg.root / 'var/backups/host-guard').mkdir(parents=True)
    (hg.root / 'var/backups/host-guard/db-1.sql.gz.gpg').write_text('x')
    assert hg.main(['uninstall', '--purge', '--yes']) == 1
    assert state(hg)['version'] == '0.3.0'
    assert hg.main(['uninstall', '--purge', '--delete-backups', '--yes']) == 0
    assert not (hg.root / 'opt/host-guard').exists() and not (hg.root / 'etc/host-guard').exists()
    assert not (hg.root / 'var/backups/host-guard').exists()


def test_an_install_made_before_the_manager_is_adopted(hg):
    sb = hg.root / 'usr/local/sbin'
    sb.mkdir(parents=True)
    (sb / 'hostguard').write_text('the old engine')
    (hg.root / 'etc/host-guard').mkdir()
    (hg.root / 'etc/host-guard/guard.conf').write_text('MAIL_TO=old@example.com\nLOGIN_USER=ubuntu\n')
    hg.use('0.3.0')
    assert hg.main(['upgrade']) == 0                       # adopting works without --mail-to
    assert '--login-user ubuntu' in read(hg, '/etc/host-guard/last-args')
    assert '--mail-to old@example.com' in read(hg, '/etc/host-guard/last-args')
    assert hg.main(['rollback', '--yes']) == 0             # back to exactly the old setup
    assert read(hg, '/usr/local/sbin/hostguard') == 'the old engine'
    assert hg.main(['uninstall', '--yes']) == 0            # and uninstall removes the old files too
    assert not (sb / 'hostguard').exists()


def test_status_and_history_run(hg, capsys):
    install(hg, '0.3.0', '--mail-to', 'a@example.com', '--login-user', 'ops')
    assert hg.main(['history']) == 0 and hg.main(['status']) == 0
    out = capsys.readouterr().out
    assert '0001-install-0.3.0' in out and 'host-guard: 0.3.0' in out


def test_the_cli_prints_help_and_rejects_unknown_commands(hg):
    assert hg.main(['--help']) == 0
    assert hg.main(['frobnicate']) == 1


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-q']))
