from subprocess import call


call("bandit -r app.py -f html -o Bandit.html", shell=True)
