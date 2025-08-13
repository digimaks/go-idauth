// SPDX-License-Identifier: EUPL-1.2

package idauth

type ScopeLevel string

const (
	// ScopeLevelRead is the read scope level.
	ScopeLevelRead ScopeLevel = "read"
	// ScopeLevelWrite is the write scope level.
	ScopeLevelWrite ScopeLevel = "write"
	// ScopeLevelDelete is the delete scope level.
	ScopeLevelDelete ScopeLevel = "delete"
	// ScopeLevelExport is the export scope level.
	ScopeLevelExport ScopeLevel = "export"
)

var scopeLevelPriorities = []ScopeLevel{
	ScopeLevelExport,
	ScopeLevelDelete,
	ScopeLevelWrite,
	ScopeLevelRead,
}
