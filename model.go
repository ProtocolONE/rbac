package rbac

const modelText = `
[request_definition]
r = req

[policy_definition]
p = sub, domain, resource, uuid, action, eft

[role_definition]
g = _, _, _
g2 = _,_

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (r.req.User == r.req.ResourceOwner && p.eft != "deny") || \  
	( \
		g(r.req.User, p.sub, r.req.Domain) && (p.domain == "*" || matchKeys(r.req.Domain, p.domain)) && \
		(p.resource == "any" || matchKeys(r.req.Resource, p.resource)) && \		
		(p.uuid == "any" || p.uuid == "skip" || matchKeys(r.req.ResourceId, p.uuid)) && \ 
		(p.action == "any" || regexMatch(r.req.Action, p.action)) && \ 
		has_access_to_resource(r.req, p.sub, p.uuid) \
	) \	
`
