# Introduction
This was a group project where the team developed different security features/hardening techniques for a Web Application Programming Interface (API) using Flask. We are required to create two versions of the project. One vulnerable version and the other secured version where we have to fix all the issues from the vulnerable version based on the [OWASP Top 10 API security.](https://owasp.org/www-project-api-security/)

&nbsp;
## Members:
- Jingling
- Laraine
- Jonathan
- Owen

&nbsp;
## Assigned OWASP API Vulnerability
<table>
  <tr>
    <th>Name</th>
    <th>Vulnerability</th>
  </tr>
  <tr>
    <td>Jingling</td>
    <td>API1: Broken Object Level Authorization <br/> API6: Mass Assignment</td>
  </tr>
  <tr>
    <td>Laraine</td>
    <td>API2: Broken User Authentication <br/> API5: Broken Function Level Authorization</td>
  </tr>
  <tr>
    <td>Jonathan</td>
    <td>API3: Excessive Data Exposure <br/> API7: Security Misconfiguration</td>
  </tr>
  <tr>
    <td>Owen</td>
    <td>API4: Lack of Resources and Rate Limiting <br/> API8: Injection</td>
  </tr>
</table>

&nbsp;
## Tools Used:
- Postman (test API)
- SQLite (open database)

&nbsp;
## Vulnerable Version
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
> [View Report](Vulnerable_Reports.md) <br/>
- Static
  - [snyk.io](https://snyk.io/)
  - [HCL AppScan CodeSweep](https://marketplace.visualstudio.com/items?itemName=HCLTechnologies.hclappscancodesweep)
- Dynamic
  - [OWASP ZAP](https://www.zaproxy.org/)
  - [Bandit](https://pypi.org/project/bandit/)

&nbsp;
## Secured Version
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
