from sentinelcode.models.policy import Policy


DEFAULT_POLICY = Policy(
    name="default-coding-agent-policy",
    allowed_tools=[
        "filesystem",
        "shell",
        "network",
    ],
    blocked_resources=[
        ".env",
        ".ssh",
        "id_rsa",
        "id_ed25519",
    ],
    allowed_commands=[
        "pytest",
        "python",
        "git",
        "npm",
    ],
    allowed_network_hosts=[
        "github.com",
        "pypi.org",
        "npmjs.com",
    ],
)