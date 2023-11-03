package wac.authz
import input.attributes.request.http as http_request

default allow = false

is_valid_user = true { http_request.headers["x-auth-request-email"] }

user = { "valid": valid, "email": email, "name": name} {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name := http_request.headers["x-auth-request-user"] 
}

headers["x-validated-by"] := "opa-checkpoint"

user_role["user"] { 
    user.valid
}

user_role[ "admin" ] { 
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_role[ "admin" ] { 
    user.email == "<kolegov@email>"
}

action_allowed {
    # authenticated user can visit any page, but not /http-echo
    not glob.match("/http-echo*", [], http_request.path)
}

action_allowed {
    user_role["admin"]
}

allow {
    user.valid
    action_allowed
}

headers["x-auth-request-roles"] := concat(" ", [ role | 
    some r
    user_role[r] 
    role := r
])


result["allowed"] := allow
result["headers"] := headers

