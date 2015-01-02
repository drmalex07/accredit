README (IIS8)
============

In order to serve as a reverse-proxied application under IIS8 webserver (using URL Rewrite module),
some extra care is needed, as redirection to external domains cannot be performed (as far as i know).

So, modify:
1. openid.message.OPENID1_URL_LIMIT to 0: force OpenID responses to be sent as 
   auto-submitted HTML forms.
2. accredit.controllers.users:logged_out action so that it redirects (came_from) 
   through HTML head meta tags (see redirect.html template).
