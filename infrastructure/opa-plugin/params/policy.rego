package wac.authz
import input.attributes.request.http as http_request

default allow = false

is_valid_user = true { http_request.headers["x-forwarded-email"] }

user = { "valid": valid, "email": email, "name": name} {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name := http_request.headers["x-auth-request-user"]
}

allow {
    user.valid
    action_allowed
}

action_allowed {
    # authenticated user can visit any page, but not /http-echo
    not glob.match("/http-echo*", [], http_request.path)
}

action_allowed {
    # or if path is /http-echo then check query string if user is admin - yes, not safe
    glob.match("/http-echo*", [], http_request.path)
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

action_allowed {
    # or my colleague can visit my /http-echo
    glob.match("/http-echo*", [], http_request.path)
    user.email == "<kolegov@email>"
}
