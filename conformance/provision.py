"""Provisions the realm the suite tests, through the administration API of
the node run.sh started: a person, the clients the suite signs in with, and
a configuration of the suite for each plan, written 0600 under --out.

Standard library only, run isolated (python3 -I). It prints no secret: under
GitHub Actions it prints the lines that mask each one first, and nothing else
of them.
"""

import argparse
import base64
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

RESPONSE_TYPES = [
    "code",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
]
SCOPES = ["openid", "profile", "email", "offline_access"]

# Each attribute the profile scope says, as OpenID Connect Core 1.0, section
# 5.1, writes it: the suite checks the form of each.
PROFILE = {
    "given_name": "Test",
    "family_name": "Person",
    "middle_name": "Quinn",
    "nickname": "tester",
    "profile": "https://example.org/tester",
    "picture": "https://example.org/tester.png",
    "website": "https://example.org",
    "gender": "female",
    "birthdate": "1990-06-15",
    "zoneinfo": "Europe/Paris",
    "locale": "en-US",
}


class Refused(Exception):
    pass


def read_arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--node", required=True, help="where the data plane listens")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--suite", required=True, help="the base URL of the suite")
    parser.add_argument("--alias", required=True)
    parser.add_argument("--admin-client", required=True)
    parser.add_argument("--admin-secret-file", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def mask(value):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::add-mask::" + value, flush=True)


def encode_basic(client_id, secret):
    # RFC 6749, section 2.3.1: each half form-encoded, then the pair.
    pair = urllib.parse.quote(client_id, safe="") + ":" + urllib.parse.quote(secret, safe="")
    return base64.b64encode(pair.encode()).decode()


def mask_client(client_id, secret):
    mask(secret)
    mask(encode_basic(client_id, secret))


def send(node, method, path, headers, body):
    request = urllib.request.Request(node + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            return answer.status, json.loads(answer.read() or b"null")
    except urllib.error.HTTPError as refused:
        # The code of the refusal alone: a body is never printed.
        try:
            code = json.loads(refused.read()).get("code") or "?"
        except ValueError:
            code = "?"
        raise Refused("{} {}: {} {}".format(method, path, refused.code, code)) from None


def take_admin_token(node, realm, client_id, secret):
    status, granted = send(
        node,
        "POST",
        "/realms/{}/oauth2/token".format(realm),
        {
            "Authorization": "Basic " + encode_basic(client_id, secret),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        b"grant_type=client_credentials&scope=admin",
    )
    if status != 200:
        raise Refused("token: {}".format(status))
    mask(granted["access_token"])
    return granted["access_token"]


def write_json(node, method, path, token, document):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    return send(node, method, path, headers, json.dumps(document).encode())


def create_person(node, realm, token):
    password = secrets.token_urlsafe(24)
    mask(password)
    _, created = write_json(
        node,
        "POST",
        "/admin/v1/realms/{}/users".format(realm),
        token,
        {
            "username": "tester",
            "email": "tester@example.org",
            "display_name": "Test Person",
            "password": password,
        },
    )
    write_json(
        node,
        "PUT",
        "/admin/v1/realms/{}/users/{}/attributes".format(realm, created["id"]),
        token,
        {"attributes": PROFILE},
    )
    return "tester", password


def create_client(node, realm, token, client):
    # Confidential, and let off a verifier: the suite sends none but in the
    # one module that tests it, and answers for its nonce instead. Each
    # person allows it on a page, as a grant offline needs (OpenID Connect
    # Core 1.0, section 11): the module of refresh tokens asks for one.
    wanted = {
        "scopes": SCOPES,
        "response_types": RESPONSE_TYPES,
        "id_token_signed_response_alg": "RS256",
        "require_pkce": False,
        "consent": True,
        **client,
    }
    _, created = write_json(node, "POST", "/admin/v1/realms/{}/clients".format(realm), token, wanted)
    secret = created["client_secret"]
    mask_client(client["client_id"], secret)
    return {"client_id": client["client_id"], "client_secret": secret}


def write_tasks(origin, realm, callback, person, first=()):
    """What the browser of the suite does from the authorization endpoint:
    signs in, allows when asked, and waits to be back on the suite."""
    username, password = person
    return [
        {
            "task": "Sign in",
            "optional": True,
            "match": "{}/realms/{}/login*".format(origin, realm),
            "commands": [
                *first,
                ["text", "name", "username", username],
                ["text", "name", "password", password],
                ["click", "xpath", "//form[@action='/realms/{}/login']//button[@type='submit']".format(realm)],
            ],
        },
        {
            "task": "Allow",
            "optional": True,
            "match": "{}/realms/{}/consent*".format(origin, realm),
            "commands": [["click", "xpath", "//button[@name='decision' and @value='allow']"]],
        },
        {
            "task": "Back on the suite",
            "match": callback + "*",
            "commands": [["wait", "id", "submission_complete", 10]],
        },
    ]


def write_authorize(origin, realm, callback, person, first=()):
    return {
        "match": "{}/realms/{}/oauth2/authorize*".format(origin, realm),
        "tasks": write_tasks(origin, realm, callback, person, first),
    }


def capture(text, optional=False):
    """Fills the placeholder of the module with the page, once `text` shows."""
    action = "update-image-placeholder-optional" if optional else "update-image-placeholder"
    return ["wait", "xpath", "//*", 10, text, action]


def write_logout(origin, realm, tasks):
    return {"match": "{}/realms/{}/oauth2/logout*".format(origin, realm), "tasks": tasks}


def write_leaving(origin, realm, returned):
    """What the browser does from the end-session endpoint: it is back on
    the suite at `returned`."""
    return write_logout(origin, realm, [{"task": "Back on the suite", "match": returned + "*"}])


def write_sign_in_overrides(origin, realm, callback, person):
    """The modules that want a screenshot of a page of the endpoint: each
    override replaces the whole script of its module."""
    again = [capture("Sign in", optional=True)]
    refused = {
        "match": "{}/realms/{}/oauth2/authorize*".format(origin, realm),
        "tasks": [
            {
                "task": "Show the refusal of the address",
                "match": "{}/realms/{}/oauth2/authorize*".format(origin, realm),
                "commands": [capture("not one the client registered")],
            }
        ],
    }
    return {
        "oidcc-prompt-login": {"browser": [write_authorize(origin, realm, callback, person, again)]},
        "oidcc-max-age-1": {"browser": [write_authorize(origin, realm, callback, person, again)]},
        "oidcc-ensure-registered-redirect-uri": {"browser": [refused]},
    }


def write_logout_overrides(origin, realm, callback, person):
    authorize = write_authorize(origin, realm, callback, person)
    logout = "{}/realms/{}/oauth2/logout*".format(origin, realm)
    confirmed = "{}/realms/{}/oauth2/logout/confirm*".format(origin, realm)

    def shown(text):
        return [{"task": "Show the page", "match": logout, "commands": [capture(text)]}]

    signed_out = [
        {
            "task": "Sign out",
            "match": logout,
            "commands": [["click", "xpath", "//form[contains(@action,'/oauth2/logout/confirm')]//button"]],
        },
        {"task": "Show that it signed out", "match": confirmed, "commands": [capture("You are signed out")]},
    ]
    pages = {
        "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri": shown("not registered for it"),
        "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri": shown("not registered for it"),
        "oidcc-rp-initiated-logout-modified-id-token-hint": shown("Do you want to sign out"),
        "oidcc-rp-initiated-logout-bad-id-token-hint": shown("Do you want to sign out"),
        "oidcc-rp-initiated-logout-no-id-token-hint": shown("Do you want to sign out"),
        "oidcc-rp-initiated-logout-no-post-logout-redirect-uri": shown("You are signed out"),
        "oidcc-rp-initiated-logout-no-params": signed_out,
        "oidcc-rp-initiated-logout-only-state": signed_out,
    }
    return {
        module: {"browser": [authorize, write_logout(origin, realm, tasks)]}
        for module, tasks in pages.items()
    }


def write_configuration(path, document):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(document, file, indent=1)


def main():
    arguments = read_arguments()
    issuer = arguments.issuer.rstrip("/")
    origin, _, realm = issuer.partition("/realms/")
    if not realm or "/" in realm:
        sys.exit("provision.py: the issuer is not {origin}/realms/{realm}: " + issuer)
    node = arguments.node.rstrip("/")
    base = "{}/test/a/{}".format(arguments.suite.rstrip("/"), arguments.alias)
    callback = base + "/callback"
    with open(arguments.admin_secret_file) as file:
        admin_secret = file.read().strip()

    try:
        token = take_admin_token(node, realm, arguments.admin_client, admin_secret)
        person = create_person(node, realm, token)
        signing_in = {"redirect_uris": [callback]}
        signing_out = {**signing_in, "post_logout_redirect_uris": [base + "/post_logout_redirect"]}
        clients = {
            "client": create_client(node, realm, token, {"client_id": "suite-first", **signing_in}),
            "client2": create_client(node, realm, token, {"client_id": "suite-second", **signing_in}),
            "client_secret_post": create_client(
                node,
                realm,
                token,
                {
                    "client_id": "suite-post",
                    "token_endpoint_auth_method": "client_secret_post",
                    **signing_in,
                },
            ),
        }
        rp_initiated = create_client(node, realm, token, {"client_id": "suite-logout", **signing_out})
        front_channel = create_client(
            node,
            realm,
            token,
            {
                "client_id": "suite-frontchannel",
                "frontchannel_logout_uri": base + "/frontchannel_logout",
                **signing_out,
            },
        )
    except Refused as refused:
        sys.exit("provision.py: refused: {}".format(refused))

    authorize = write_authorize(origin, realm, callback, person)
    signing_out_back = write_leaving(origin, realm, base + "/post_logout_redirect")
    common = {
        "alias": arguments.alias,
        "server": {"discoveryUrl": issuer + "/.well-known/openid-configuration"},
    }
    sign_in_overrides = write_sign_in_overrides(origin, realm, callback, person)
    logout_overrides = write_logout_overrides(origin, realm, callback, person)
    families = {
        "basic.json": "Basic",
        "formpost-basic.json": "Form Post Basic",
        "implicit.json": "Implicit",
        "formpost-implicit.json": "Form Post Implicit",
        "hybrid.json": "Hybrid",
        "formpost-hybrid.json": "Form Post Hybrid",
        "config.json": "Config",
    }
    configurations = os.path.join(arguments.out, "configs")
    os.makedirs(configurations, mode=0o700, exist_ok=True)
    for name, family in families.items():
        write_configuration(
            os.path.join(configurations, name),
            {
                "description": "saffui, " + family,
                **common,
                **clients,
                "browser": [authorize],
                "override": sign_in_overrides,
            },
        )
    for name, family, client in [
        ("rp-initiated-logout.json", "RP-Initiated Logout", rp_initiated),
        ("frontchannel-logout.json", "Front-Channel Logout", front_channel),
    ]:
        write_configuration(
            os.path.join(configurations, name),
            {
                "description": "saffui, " + family,
                **common,
                "client": client,
                "browser": [authorize, signing_out_back],
                "override": logout_overrides,
            },
        )
    print("provision.py: a person, 5 clients and {} configurations".format(len(families) + 2))


if __name__ == "__main__":
    main()
