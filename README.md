# UpdateACCaccountUsers
example code use at own risk: updates default company and default role for ACC accounts users based on csv

<pre>
created by openai gpt based on the following prompt:
"Hi, I need a C# script that leverages APS ACC API to update default company and default role for account users on an ACC account. Given a csv file with columns: email, default company, default role. For simplicity - if possible - do not use the APS .NET SDK, but the core REST calls offered by APS API."

Code worked (Visual Studio Console app), but needed some correction:
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
