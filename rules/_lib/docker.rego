# Helper package — not a rule.
# Parses Dockerfiles from input.file_contents into instruction lists.
# Used by aquasecurity-trivy-checks Docker ports.

package vulnetix.trivy.docker

import rego.v1

is_dockerfile_path(path) if {
	lower_path := lower(path)
	parts := split(lower_path, "/")
	last := parts[count(parts) - 1]
	_is_dockerfile_name(last)
}

_is_dockerfile_name(name) if name == "dockerfile"

_is_dockerfile_name(name) if startswith(name, "dockerfile.")

_is_dockerfile_name(name) if endswith(name, ".dockerfile")

_is_dockerfile_name(name) if contains(name, "dockerfile")

# Normalise line continuations (backslash + newline) to a single space.
_normalised(content) := replace(content, "\\\n", " ")

# Instructions (list of {cmd, value, line}) for a file's content.
instructions(content) := out if {
	lines := split(_normalised(content), "\n")
	out := [inst |
		some i, line in lines
		trimmed := trim_space(line)
		trimmed != ""
		not startswith(trimmed, "#")
		parts := regex.split(`\s+`, trimmed)
		count(parts) >= 1
		cmd := lower(parts[0])
		value := trim_space(substring(trimmed, count(parts[0]), -1))
		inst := {"cmd": cmd, "value": value, "line": i + 1, "original": trimmed}
	]
}

# Instructions of a specific type (e.g. "run", "from").
instructions_of_type(content, typ) := [inst |
	some inst in instructions(content)
	inst.cmd == lower(typ)
]

# All files keyed by path for convenience.
dockerfiles := [{"path": path, "content": content} |
	some path, content in input.file_contents
	is_dockerfile_path(path)
]

# Stages: trivy groups commands under each FROM. A stage entry:
#   {path, from_index, from_line, from_image, alias, instructions}
stages := [s |
	some f in dockerfiles
	some s in _stages_for(f.path, f.content)
]

_stages_for(path, content) := out if {
	insts := instructions(content)
	from_positions := [i | some i, inst in insts; inst.cmd == "from"]
	out := [s |
		some idx, pos in from_positions
		end := _next_from(from_positions, idx, count(insts))
		from_inst := insts[pos]
		parts := regex.split(`(?i)\s+AS\s+`, from_inst.value)
		image := trim_space(parts[0])
		alias := _stage_alias(parts)
		stage_insts := [ins | some j in numbers.range(pos, end - 1); ins := insts[j]]
		s := {
			"path": path,
			"from_index": idx,
			"from_line": from_inst.line,
			"from_image": image,
			"alias": alias,
			"instructions": stage_insts,
		}
	]
}

_next_from(positions, idx, total) := positions[idx + 1] if idx + 1 < count(positions)

_next_from(positions, idx, total) := total if idx + 1 == count(positions)

_stage_alias(parts) := trim_space(parts[1]) if count(parts) > 1

_stage_alias(parts) := "" if count(parts) <= 1

# Convenience queries across all dockerfiles.
# Each entry: {path, cmd, value, line}
from_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "from")
	e := object.union({"path": f.path}, inst)
]

add_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "add")
	e := object.union({"path": f.path}, inst)
]

copy_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "copy")
	e := object.union({"path": f.path}, inst)
]

run_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "run")
	e := object.union({"path": f.path}, inst)
]

expose_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "expose")
	e := object.union({"path": f.path}, inst)
]

user_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "user")
	e := object.union({"path": f.path}, inst)
]

healthcheck_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "healthcheck")
	e := object.union({"path": f.path}, inst)
]

maintainer_cmds := [e |
	some f in dockerfiles
	some inst in instructions_of_type(f.content, "maintainer")
	e := object.union({"path": f.path}, inst)
]

# True if value is a JSON-array exec form.
is_json_array(value) if regex.match(`^\s*\[.*\]\s*$`, value)

# Parse a JSON-array exec form; returns [] if not a JSON array.
json_exec_args(value) := out if {
	is_json_array(value)
	out := json.unmarshal(value)
} else := []

# Extract a snippet of content around a 1-based line.
snippet_at(content, line_num, window) := out if {
	lines := split(content, "\n")
	total := count(lines)
	start := max([0, line_num - 1 - window])
	end := min([total, line_num + window])
	out := concat("\n", array.slice(lines, start, end))
}

max([a, b]) := a if a >= b

max([a, b]) := b if a < b

min([a, b]) := a if a <= b

min([a, b]) := b if a > b

# Convenience: split RUN commands by && / ;
split_run(command) := regex.split(`\s*(?:&&|;)\s*`, command)

# Check if a RUN command includes a given sub-command token.
run_contains(command, token) if contains(command, token)
