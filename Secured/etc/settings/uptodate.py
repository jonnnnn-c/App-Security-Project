import json
import subprocess
import time


def report(option):
    print("\n================================================================================")

    print('Checking if PIP is up to date...')
    subprocess.call("python -m pip install --upgrade pip", shell=True)

    print('\nChecking for vulnerabilities in the current packages...\n')
    safety = subprocess.Popen(['safety', 'check'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = safety.communicate()[0]
    print(output.decode())

    # ======= Checks for outdated packages ======
    out1 = subprocess.Popen('pip list --outdated --format json', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = out1.communicate()

    outdated = []
    loaded_json = json.loads(stdout)
    for x in loaded_json:
        outdated.append(x['name'])

    # ======== Checks for vulnerabilities ========
    out = subprocess.Popen('safety check --bare', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()

    vulnerable = []
    for x in stdout.decode().split():
        vulnerable.append(x)
    # ============================================

    if len(vulnerable) != 0 or len(outdated) != 0:
        print("There is {} package(s) with known vulnerabilities:".format(len(vulnerable)))
        if len(vulnerable) > 0:
            for i in vulnerable:
                print('•', i, '[Vulnerable]')
        else:
            print('• NONE')

        print("\nThere is {} package(s) that have new updates:".format(len(outdated)))
        if len(outdated) > 0:
            for x in outdated:
                print('•', x, '[Outdated]')
        else:
            print('• NONE')

        if option.lower() == 'true':
            return update(vulnerable, outdated)
        else:
            print('\n Update recommended')
            print("================================================================================\n")
            return True

    else:
        print("There are no known vulnerabilities or new updates to the packages.")
        print("================================================================================\n")
        return True


def update(outdated, vulnerable):
    proceed = input("\nDo you want to update the packages? [Y/N]: ")

    if proceed.lower() == 'y':
        if len(vulnerable) != 0:
            print('\nAuto-updating vulnerable package to the latest version...')
            for i in vulnerable:
                vul = subprocess.Popen("pip install --upgrade {}".format(i), stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
                output = vul.communicate()[0]
                print(output.decode())

        if len(outdated) != 0:
            print('\nAuto-updating package to the latest version...')
            for i in outdated:
                dated = subprocess.Popen("pip install --upgrade {}".format(i), stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT)
                output = dated.communicate()[0]
                print(output.decode())

        subprocess.Popen("pip freeze > etc/settings/requirements.txt", stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)  # updates the requirement.txt file
        print('Update Completed!\nServer Restarting...')
        print("================================================================================\n")
        return False

    elif proceed.lower() == 'n':
        print('\nUpdate was skipped.')
        print("================================================================================\n")
        return True
