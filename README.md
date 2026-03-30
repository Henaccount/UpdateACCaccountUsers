# UpdateACCaccountUsers
example code use at own risk: updates default company and default role for ACC accounts users based on csv

<table border=1><tr><td><i>Disclaimer – AI-Generated Code

This code was generated in whole or in part using artificial intelligence tools. While efforts have been made to review and validate the output, AI-generated code may contain errors, omissions, or unintended behavior.

Users of this code should be aware that:

The code may not follow best practices for security, performance, or reliability.
Vulnerabilities may be present, including but not limited to injection flaws, insecure dependencies, or improper handling of data.
The code may be susceptible to issues arising from prompt manipulation (e.g., prompt injection) or unintended generation of unsafe logic.
No guarantees are made regarding correctness, completeness, or fitness for a particular purpose.

It is strongly recommended that this code be thoroughly reviewed, tested, and audited—especially before use in production or security-sensitive environments.

The authors disclaim any liability for damages or issues arising from the use of this code.</i></td></tr></table>

<pre>
created by openai gpt based on the following prompt:
"Hi, I need a C# script that leverages APS ACC API to update default company and default role for account users on an ACC account. Given a csv file with columns: email, default company, default role. For simplicity - if possible - do not use the APS .NET SDK, but the core REST calls offered by APS API."

Code worked (Visual Studio Console app), but needed some manual correction:
ai thought that the role needs to be resolved, but that's not the case. Also the role attribute is called default_role and not default_role_id. There might be still some misleadings parts remaining in the code. Note that this script has not been tested sufficiently, even though it worked on a small test.

CSV example:
email,default company,default role
theuser1@domain.de,TheNewDefaultCompany,TheNewDefaultRole
theuser2@domain.de,TheNewDefaultCompany,TheNewDefaultRole

example call via Dos prompt:
UpdateACCaccountUsers --clientId xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --clientSecret xxxxxxxxxxxxxxxx --accountId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --csv "C:\Users\theuser\Downloads\users.csv" --region US --scope "account:read account:write" --impersonateUserId xxxxxxxxxxxx

impersonateUserId is Oxygen ID
e.g. look up in ACC Insight data connector (admin_users.csv from downloaded zip)
</pre>
