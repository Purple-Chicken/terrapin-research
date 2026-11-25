# STATUS: SKETCH, NOT FUNCTIONAL. Not loaded, not syntax-checked against a
# real Metasploit install (this sandbox has no Ruby/msf framework, and no
# time was spent trying to add one -- the effort went into making
# attack/cli.py real and tested instead, per the write-up's "alternatively,
# a standalone CLI tool" option). This file exists purely to document the
# shape of the "Metasploit module" half of roadmap item 3 ("Automation"),
# so it's a short port instead of a blank page once someone has a real
# msfconsole to test it in.
#
# Design: this module does NOT reimplement the BPP relay logic in Ruby.
# It's meant to be a thin wrapper that shells out to attack/relay.py
# (already written, unit-tested, and validated against a real OpenSSH
# binary in attack/cli.py's place) and reports the datastore options
# Msf::Exploit modules are expected to expose, per the write-up:
# "parameterized by target, cipher mode, and message count."

require "msf/core"

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        "Name" => "Terrapin (CVE-2023-48795) RcvIncrease Sanity Check",
        "Description" => %q{
          Wraps attack/relay.py to inject one or more SSH_MSG_IGNORE
          packets into an SSH handshake's client-bound stream before
          NEWKEYS (the RcvIncrease primitive), optionally paired with a
          compensating server->client message deletion for full prefix
          truncation (see attack/truncation_profiles.py). Reports whether
          the handshake survived (vulnerable, non-strict-kex pairing) or
          was rejected (patched, strict-kex).
        },
        "Author" => ["Purple-Chicken terrapin-research project"],
        "References" => [
          ["CVE", "2023-48795"],
          ["URL", "https://terrapin-attack.com/"],
        ],
        "License" => MSF_LICENSE,
        "Actions" => [["Check"]],
        "DefaultAction" => "Check",
      )
    )

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(22),
        OptEnum.new("SSH_TARGET", [true, "logical target name (see attack/targets.py)",
                                    "openssh", %w[openssh dropbear russh gitea-ssh podman-api]]),
        OptString.new("CIPHER", [false, "force this client cipher (blank = let ssh negotiate)", ""]),
        OptInt.new("MESSAGE_COUNT", [true, "number of SSH_MSG_IGNORE packets to inject", 1]),
        OptBool.new("FULL_TRUNCATION", [true, "also attempt the compensating deletion (item 2)", false]),
        OptPath.new("RELAY_PY", [true, "path to attack/relay.py", "attack/relay.py"]),
      ]
    )
  end

  # NOT IMPLEMENTED: launching relay.py as a child process, proxying this
  # module's own SSH session through it, and parsing the resulting
  # relay.jsonl for handshake_complete vs handshake_failed -- the same
  # classification scripts/check_log.py already does for both branches'
  # traces. Porting that parsing logic here (instead of shelling out to
  # Python) is the remaining work before this is real.
  def run
    print_error("sketch only -- see the file's header comment. Use attack/cli.py instead, which is real and tested.")
  end
end
