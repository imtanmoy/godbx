package godbx

import (
	"fmt"
	"github.com/go-pg/pg/v9"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// See http://www.postgresql.org/docs/9.3/static/errcodes-appendix.html for
// a full listing of the error codes present here.
const (
	CodeNumericValueOutOfRange    = "22003"
	CodeInvalidTextRepresentation = "22P02"
	CodeNotNullViolation          = "23502"
	CodeForeignKeyViolation       = "23503"
	CodeUniqueViolation           = "23505"
	CodeCheckViolation            = "23514"
	CodeLockNotAvailable          = "55P03"
)

// SQLError is a human-readable database error. Message should always be a
// non-empty, readable string, and is returned when you call err.Error(). The
// other fields may or may not be empty.
type SQLError struct {
	Message    string
	Code       string
	Constraint string
	Severity   string
	Routine    string
	Table      string
	Detail     string
	Column     string
	err        error
}

func (sqlError *SQLError) Error() string {
	return sqlError.Message
}

func (sqlError *SQLError) Cause() error {
	return sqlError.err
}

// Constraint is a custom database check constraint you've defined, like "CHECK
// balance > 0". Postgres doesn't define a very useful message for constraint
// failures (new row for relation "accounts" violates check constraint), so you
// can define your own. The Name should be the name of the constraint in the
// database. Define GetError to provide your own custom error handler for this
// constraint failure, with a custom message.
type Constraint struct {
	Name         string
	ParsePgError func(*pg.Error) *SQLError
}

var constraintMap = map[string]*Constraint{}
var constraintMu sync.RWMutex

// capitalize the first letter in the string
func capitalize(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	return fmt.Sprintf("%c", unicode.ToTitle(r)) + s[size:]
}

var columnFinder = regexp.MustCompile(`Key \((.+)\)=`)
var valueFinder = regexp.MustCompile(`Key \(.+\)=\((.+)\)`)

// findColumn finds the column in the given pq Detail error string. If the
// column does not exist, the empty string is returned.
//
// detail can look like this:
//    Key (id)=(3c7d2b4a-3fc8-4782-a518-4ce9efef51e7) already exists.
func findColumn(detail string) string {
	results := columnFinder.FindStringSubmatch(detail)
	if len(results) < 2 {
		return ""
	} else {
		return results[1]
	}
}

// findColumn finds the column in the given pq Detail error string. If the
// column does not exist, the empty string is returned.
//
// detail can look like this:
//    Key (id)=(3c7d2b4a-3fc8-4782-a518-4ce9efef51e7) already exists.
func findValue(detail string) string {
	results := valueFinder.FindStringSubmatch(detail)
	if len(results) < 2 {
		return ""
	} else {
		return results[1]
	}
}

var foreignKeyFinder = regexp.MustCompile(`not present in table "(.+)"`)

// findForeignKeyTable finds the referenced table in the given pq Detail error
// string. If we can't find the table, we return the empty string.
//
// detail can look like this:
//    Key (account_id)=(91f47e99-d616-4d8c-9c02-cbd13bceac60) is not present in table "accounts"
func findForeignKeyTable(detail string) string {
	results := foreignKeyFinder.FindStringSubmatch(detail)
	if len(results) < 2 {
		return ""
	}
	return results[1]
}

var parentTableFinder = regexp.MustCompile(`update or delete on table "([^"]+)"`)

func findParentTable(message string) string {
	match := parentTableFinder.FindStringSubmatch(message)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// ParsePgError parses a given database error and returns a human-readable
// version of that error. If the error is unknown, it's returned as is,
// however, all errors of type `pg.Error` are re-thrown as an Error, so it's
// impossible to get a `pg.Error` back from this function.
// https://www.postgresql.org/docs/10/protocol-error-fields.html
func ParsePgError(err error) error {
	if err == nil {
		return nil
	}
	if pgErr, ok := err.(pg.Error); ok {
		code := pgErr.Field('C')
		detail := pgErr.Field('D')
		message := pgErr.Field('M')
		severity := pgErr.Field('S')
		constraint := pgErr.Field('n')
		table := pgErr.Field('t')
		column := pgErr.Field('c')
		routine := pgErr.Field('R')
		switch code {
		case CodeUniqueViolation:
			columnName := findColumn(detail)
			if columnName == "" {
				columnName = "value"
			}
			valueName := findValue(detail)
			var msg string
			if valueName == "" {
				msg = fmt.Sprintf("a %s already exists with that value", columnName)
			} else {
				msg = fmt.Sprintf("a %s already exists with this value (%s)", columnName, valueName)
			}
			dbe := &SQLError{
				Message:    msg,
				Code:       code,
				Severity:   severity,
				Constraint: constraint,
				Table:      table,
				Detail:     detail,
				err:        err,
			}
			if columnName != "value" {
				dbe.Column = columnName
			}
			return dbe
		case CodeForeignKeyViolation:
			columnName := findColumn(detail)
			if columnName == "" {
				columnName = "value"
			}
			foreignKeyTable := findForeignKeyTable(detail)
			var tablePart string
			if foreignKeyTable == "" {
				tablePart = "in the parent table"
			} else {
				tablePart = fmt.Sprintf("in the %s table", foreignKeyTable)
			}
			valueName := findValue(pgErr.Field('D'))
			var msg string
			switch {
			case strings.Contains(message, "update or delete"):
				parentTable := findParentTable(message)
				// in this case table contains the child table. there's
				// probably more work we could do here.
				msg = fmt.Sprintf("Can't update or delete %[1]s records because the %[1]s %s (%s) is still referenced by the %s table", parentTable, columnName, valueName, table)
			case valueName == "":
				msg = fmt.Sprintf("Can't save to %s because the %s isn't present %s", table, columnName, tablePart)
			default:
				msg = fmt.Sprintf("Can't save to %s because the %s (%s) isn't present %s", table, columnName, valueName, tablePart)
			}
			return &SQLError{
				Message:    msg,
				Code:       code,
				Column:     column,
				Constraint: constraint,
				Table:      table,
				Routine:    routine,
				Severity:   severity,
				err:        err,
			}
		case CodeNumericValueOutOfRange:
			msg := strings.Replace(message, "out of range", "too large or too small", 1)
			return &SQLError{
				Message:  capitalize(msg),
				Code:     code,
				Severity: severity,
				err:      err,
			}
		case CodeInvalidTextRepresentation:
			msg := message
			// Postgres tweaks with the message, play whack-a-mole until we
			// figure out a better method of dealing with these.
			if !strings.Contains(message, "invalid input syntax for type") {
				msg = strings.Replace(message, "input syntax for", "input syntax for type", 1)
			}
			msg = strings.Replace(msg, "input value for enum ", "", 1)
			msg = strings.Replace(msg, "invalid", "Invalid", 1)
			return &SQLError{
				Message:  msg,
				Code:     code,
				Severity: severity,
				err:      err,
			}
		case CodeNotNullViolation:
			msg := fmt.Sprintf("No %[1]s was provided. Please provide a %[1]s", column)
			return &SQLError{
				Message:  msg,
				Code:     code,
				Column:   column,
				Table:    table,
				Severity: severity,
				err:      err,
			}
		case CodeCheckViolation:
			constraintMu.RLock()
			c, ok := constraintMap[constraint]
			constraintMu.RUnlock()
			if ok {
				return c.ParsePgError(&pgErr)
			} else {
				return &SQLError{
					Message:    message,
					Code:       code,
					Column:     column,
					Table:      table,
					Severity:   severity,
					Constraint: constraint,
					err:        err,
				}
			}
		default:
			return &SQLError{
				Message:    message,
				Code:       code,
				Column:     column,
				Constraint: constraint,
				Table:      table,
				Routine:    routine,
				Severity:   severity,
				err:        err,
			}
		}
	}
	return err
}
