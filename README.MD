# RBAC
(Hierarchical Role Based Access Control) 

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT) 
[![Build Status](https://travis-ci.org/ProtocolONE/rbac.svg?branch=master)](https://travis-ci.org/ProtocolONE/rbac) 
[![Go Report Card](https://goreportcard.com/ProtocolOne/rbac)](https://goreportcard.com/report/github.com/ProtocolOne/rbac) 
[![codecov](https://codecov.io/gh/ProtocolONE/rbac/branch/master/graph/badge.svg)](https://codecov.io/gh/ProtocolONE/rbac) 
[![GoDoc](https://godoc.org/github.com/ProtocolOne/rbac?status.svg)](http://godoc.org/github.com/ProtocolOne/rbac) 

# Motivation
We needed hierarchical role based access control for Protocol One projects based on Go. We have some specific requirements 
which could`nt be covered by [casin](https://github.com/casbin/casbin) itself:
- support for regexp matching rules for domains
- support for storing resource based permissions for each role 
- support for given users role to all owner resources or just given resources
And also we want to support all casbin features like adapters for storing policy and data, using watcher to
synchronize data across application instances. For more details look at our default model description. 

# Installation

```
go get github.com/ProtocolOne/rbac
```

# Default model 
In Protocol One most of projects use hybrid mode for access control — RBAC with domain for each role there 
domain is user business class in the system. Domain is vendor, merchant, system, etc. Right now we don`t use
tenants but it could be simple added to the model. 

After domains the most important in the RBAC is object. In our terms it is resource with attached actions and 
resource unique identity. By default each policy define role with wildcard as resource id or use pre-defined 
word `skip` to ignore advances check for object owners. 

Owners in our case is user who create and own resources. The simplest analogy is a project. So each owner in
each domain is kind of project with set of resources and permissions.

Each owner could delegate role to user for all it's resources or just for selected resources. Also role 
could be delegated with restrictions for selected resources by they identity. Such permission models 
usually could be done with storing such information in external storage. We want to store all role related
information in casbin groups.   

The model based on access effects - we deny all that not allowed.

## Resource

Depends on. It could be something like com string service.method or something more simple like shop, user management,
games and so on. In general it's one business or logic function which controlled by role. And `action` here is a list
of possible operation on resource. Like `read`, `write`, `(create)|(delete)` and so on.

We also use custom role manager on base of casbin role manager to support wildcards in domain.

## Roles

For example we have table like this in RBAC with domain:

| Role              | vendor   | merchant   | Resource   | UUID  | Action           | Effect |
|-------------------|----------|------------|------------|-------|------------------|--------|
| admin             |    х     |            | Games      |   *   |  (read)|(write)  | allow  |
| admin             |          |    х       | Games      |   1   |  read            | allow  |
| manager           |          |    х       | Analytic.* |  skip |  read            | allow  |
| support           |    х     |    х       | *          |  skip |  read            | allow  |

And our requirements:
1. Admin in domain vendor could read and write any Games.  
2. Admin in domain merchant could only read Game wih identity 1.
3. Manager in domain merchant could read any Analytic related resources.
4. Admin in domain merchant inherits Manager. 
5. Support in any domain could read anything without any permission limits.

In terms of casbin we should define it in this way:
```
p, admin, vendor, games, *, (read)|(write), allow
p, admin, merchant, games, 1, read, allow
p, manager, merchant, analytics.*, skip, read, deny
p, support, *, *, *, any, allow

# Now inheritance 
g, admin,manager,merchant 

# Roles
g,max,admin,vendor
g,tom,admin,merchant
```

In structure like this we can't handle request like "Alise want delegates role Admin to Max in domain vendor
only for own resources and just for all resources related to identity 4". In our case all resources of owner
Alice based on base object - Game. We say "Any resource of Alise relates to one or other game". To support
such feature we use special group `g2` for storing restrictions:
```
g,max,admin,vendor
g2,max,alise/*/4
``` 
Which works as 
1. Max has role Admin in domain vendor. 
2. Max role Admin works only for games of Alise
3. Max could operates any resources related to game with identity 4.  

# License

This project is licensed under the [MIT](LICENSE).
