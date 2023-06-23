package authrules

import "github.com/biscuit-auth/biscuit-go/parser"

var IfUserRoleAllowsOperation = parser.New().Must().Rule(`
 right($operation) 
	 <- user($user_id, $role),
	 operation($operation),
	 role($role, $permissions),
	 $permissions.contains($operation)
`)

var IfUserHasCustomPermissionForOperation = parser.New().Must().Rule(`
 right($operation) 
	 <- operation($operation),
	 custom_permissions($custom_permissions),
	 $custom_permissions.contains($operation)
`)

var IfUserIsOwnerHeCanWriteCard = parser.New().Must().Rule(`
 right($operation) 
	 <- operation($operation),
	 user($user_id, $user_role),
	 card_owner($user_id, $card_id),
	 card($card_id),
	 $operation == "card:write" 
`)
