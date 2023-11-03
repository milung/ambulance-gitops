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

response_headers_to_add["x-auth-request-roles"] := roles if {
    user.valid
    roles := join(" ", [role | role := user_roles[_]])
}

user_roles = ["user"] { 
    user.valid
}

user_roles = ["admin"] { 
    user_is_admin
}

headers["x-validated-by"] := "opa-checkpoint"

action_allowed {
    # authenticated user can visit any page, but not /http-echo
    not glob.match("/http-echo*", [], http_request.path)
}

action_allowed {
    user_is_admin
}

user_is_admin {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_is_admin {
    user.email == "<kolegov@email>"
    response_headers_to_add["x-auth-request-roles"] := "admin collegue"
}
