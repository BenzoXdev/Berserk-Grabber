import os
import re
from time import sleep
from zipfile import ZipFile

import requests


def _parse_version(s: str):
    """Extract version string like '1.0' or '1.2' from code."""
    m = re.search(r"self\.version\s*=\s*['\"]([^'\"]+)['\"]", s)
    return m.group(1) if m else "0.0"


def _version_less(local: str, remote: str):
    """True if local is strictly older than remote (e.g. 1.1 < 1.2)."""
    try:
        l = [int(x) for x in local.split(".")]
        r = [int(x) for x in remote.split(".")]
        for i in range(max(len(l), len(r))):
            a = l[i] if i < len(l) else 0
            b = r[i] if i < len(r) else 0
            if a < b:
                return True
            if a > b:
                return False
        return False
    except (ValueError, AttributeError):
        return False


class Update():
    def __init__(self):
        self.version = '1.1'
        self.github = 'https://raw.githubusercontent.com/BenzoXdev/Berserk-Grabber/main/tools/update.py'
        self.zipfile = 'https://github.com/BenzoXdev/Berserk-Grabber/archive/refs/heads/main.zip'
        self.update_checker()

    def update_checker(self):
        try:
            r = requests.get(self.github, timeout=15)
            r.raise_for_status()
            code = r.text
        except Exception as e:
            print('Could not check for updates:', e)
            print('Exiting...')
            sleep(2)
            return

        remote_version = _parse_version(code)
        if not _version_less(self.version, remote_version):
            print('This version is up to date! (v%s)' % self.version)
            print('Exiting...')
            sleep(2)
            return

        print('''
                    ███╗   ██╗███████╗██╗    ██╗    ██╗   ██╗██████╗ ██████╗  █████╗ ████████╗███████╗██╗
                    ████╗  ██║██╔════╝██║    ██║    ██║   ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║
                    ██╔██╗ ██║█████╗  ██║ █╗ ██║    ██║   ██║██████╔╝██║  ██║███████║   ██║   █████╗  ██║
                    ██║╚██╗██║██╔══╝  ██║███╗██║    ██║   ██║██╔═══╝ ██║  ██║██╔══██║   ██║   ██╔══╝  ╚═╝
                    ██║ ╚████║███████╗╚███╔███╔╝    ╚██████╔╝██║     ██████╔╝██║  ██║   ██║   ███████╗██╗
                    ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝      ╚═════╝ ╚═╝     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝
                                      Your version of Berserk Grabber is outdated! (v%s -> v%s)''' % (self.version, remote_version))
        choice = input('\nWould you like to update? (y/n): ')
        if choice.lower() != 'y':
            print('Exiting...')
            sleep(2)
            return

        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        zip_path = os.path.join(desktop, "Berserk-Grabber-main.zip")

        try:
            print('Downloading...')
            r = requests.get(self.zipfile, timeout=60)
            r.raise_for_status()
            with open(zip_path, 'wb') as f:
                f.write(r.content)
            print('Extracting to Desktop...')
            with ZipFile(zip_path, 'r') as filezip:
                filezip.extractall(path=desktop)
            try:
                os.remove(zip_path)
            except OSError:
                pass
            print('The new version is now on your desktop.\nUpdate Complete!')
        except Exception as e:
            print('Update failed:', e)
            if os.path.isfile(zip_path):
                try:
                    os.remove(zip_path)
                except OSError:
                    pass
        print("Exiting...")
        sleep(5)


if __name__ == '__main__':
    Update()
