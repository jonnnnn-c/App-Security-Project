# App-Security-Project
This was a group project where the team developed different security features/hardening techniques for a Web Application Programming Interface (API) using Flask. We are required to create two versions of the project. One vulnerable version and the other secured version where we have to fix all the issues from the vulnerable version based on the [OWASP Top 10 API security.](https://owasp.org/www-project-api-security/)

&nbsp;
## Members: :sunglasses:
- Jingling
- Laraine
- Jonathan
- Owen

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

### Scanning Vulnerabilities:
- Static
  - Bandit 
    > pip install bandit
  - [HCL AppScan CodeSweep](https://marketplace.visualstudio.com/items?itemName=HCLTechnologies.hclappscancodesweep)
- Dynamic
  - [OWASP ZAP](https://www.zaproxy.org/)
  - [snyk.io](https://snyk.io/)

## Secured Version :lock:
