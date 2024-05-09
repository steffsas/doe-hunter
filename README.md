# doe-hunter

[![test](https://github.com/steffsas/doe-hunter/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/steffsas/doe-hunter/actions/workflows/test.yml)
[![lint](https://github.com/steffsas/doe-hunter/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/steffsas/doe-hunter/actions/workflows/lint.yml)
[![coverage](https://raw.githubusercontent.com/steffsas/doe-hunter/badges/.badges/main/coverage.svg)](/.github/.testcoverage.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/steffsas/doe-hunter/lib?cache=v1)](https://goreportcard.com/report/github.com/steffsas/doe-hunter/lib)


`doe-hunter` is a tool to query for SVCB DNS RR (see [RFC9460](https://www.rfc-editor.org/rfc/rfc9460)) in the context of the `Discovery of Designated Resolvers` protocol (see [RFC9462](https://www.rfc-editor.org/rfc/rfc9462)) and analyzes the advertised (secure) endpoints.

