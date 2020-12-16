# App-Security-Project
This was a group project where the team developed different security features/hardening techniques for a Web Application Programming Interface (API) using Flask. We are required to create two versions of the project. One vulnerable version and the other secured version where we have to fix all the issues from the vulnerable version based on the [OWASP Top 10 API security.](https://owasp.org/www-project-api-security/)

&nbsp;
## Members: :sunglasses:
- Jingling
- Laraine
- Jonathan
- Owen

&nbsp;
## Assigned OWASP API Vulnerability
Name  | Vulnerability
------------- | -------------
Jingling  | API1: Broken Object Level Authorization <br/> API6: Mass Assignment
Laraine  | API2: Broken User Authentication <br/> API5: Broken Function Level Authorization
Jonathan  | API3: Excessive Data Exposure <br/> API7: Security Misconfiguration
Owen  | API4: Lack of Resources and Rate Limiting <br/> API8: Injection

&nbsp;
## Tools Used:
- Postman (test API)
- SQLite (open database)

&nbsp;
## Vulnerable Version :unlock:
### Requirements:
> pip install Flask <br>
> pip install Flask-Mail <br>
> pip install Flask-JWT-Extended <br>
> pip install Flask-SQLAlchemy <br>
> pip install flask-Marshmallow <br>
> pip install flask-rest-paginate <br>
> pip install itsdangerous <br>

&nbsp;
### Scanning Vulnerabilities:
> [View Report](Vulnerable/Reports)
- Static
  - [snyk.io](https://snyk.io/)
  - [HCL AppScan CodeSweep](https://marketplace.visualstudio.com/items?itemName=HCLTechnologies.hclappscancodesweep)
- Dynamic
  - [OWASP ZAP](https://www.zaproxy.org/)
  - [Bandit](https://pypi.org/project/bandit/)

&nbsp;
## Secured Version :lock:
### Requirements:
> pip install Flask <br>
> pip install Flask-Mail <br>
> pip install Flask-JWT-Extended <br>
> pip install Flask-SQLAlchemy <br>
> pip install Flask-RESTful <br>
> pip install Flask-Limiter <br>
> pip install flask-Marshmallow <br>
> pip install flask-talisman <br>
> pip install itsdangerous <br>
> pip install twilio <br>
> pip install bcrypt <br>
> pip install pyotp <br>
> pip install cryptography <br>
> pip install APScheduler <br>
> pip install safety <br>
> pip install pyOpenSSL <br>

&nbsp;
