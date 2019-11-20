extern crate rbac;

use std::collections::HashSet;

use rbac::*;

#[derive(Debug, PartialEq, Eq, Hash)]
struct MyUser {
    id: u32,
}

impl Identifiable for MyUser {
    type Id = u32;

    fn get_rbac_id(&self) -> Self::Id {
        self.id
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct MyRole {
    id: u32,
}

impl Identifiable for MyRole {
    type Id = u32;

    fn get_rbac_id(&self) -> Self::Id {
        self.id
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct MyPermission {
    id: u32,
}

impl Identifiable for MyPermission {
    type Id = u32;

    fn get_rbac_id(&self) -> Self::Id {
        self.id
    }
}

// gandalf is administrator
// elrond is supervisor
// sam is agent and salesperson
// legolas is salesperson
// frodo has no role
fn test_environment() -> (
    InMemoryRbac<MyUser, MyRole, MyPermission>,
    Vec<MyUser>,
    Vec<MyRole>,
    Vec<MyPermission>,
) {
    let mut memory: InMemoryRbac<MyUser, MyRole, MyPermission> = InMemoryRbac::new();

    let gandalf = MyUser { id: 10 };
    let elrond = MyUser { id: 11 };
    let sam = MyUser { id: 12 };
    let legolas = MyUser { id: 13 };
    let frodo = MyUser { id: 14 };

    let agent = MyRole { id: 110 };
    let salesperson = MyRole { id: 111 };
    let supervisor = MyRole { id: 112 };
    let administrator = MyRole { id: 113 };

    let make_calls = MyPermission { id: 210 };
    let enter_information = MyPermission { id: 211 };
    let generate_form = MyPermission { id: 212 };
    let alter_state = MyPermission { id: 213 };
    let unlimited_lookups = MyPermission { id: 214 };

    memory.assign_role(&gandalf, &administrator).unwrap();
    memory.assign_role(&elrond, &supervisor).unwrap();
    memory.assign_role(&sam, &agent).unwrap();
    memory.assign_role(&sam, &salesperson).unwrap();
    memory.assign_role(&legolas, &salesperson).unwrap();

    memory.add_permission(&agent, &make_calls).unwrap();
    memory.add_permission(&agent, &enter_information).unwrap();
    memory.add_permission(&salesperson, &generate_form).unwrap();
    memory.add_permission(&supervisor, &make_calls).unwrap();
    memory
        .add_permission(&supervisor, &enter_information)
        .unwrap();
    memory.add_permission(&supervisor, &generate_form).unwrap();
    memory.add_permission(&supervisor, &alter_state).unwrap();

    let users = vec![gandalf, elrond, sam, legolas, frodo];
    let roles = vec![agent, salesperson, supervisor, administrator];
    let permissions = vec![
        make_calls,
        enter_information,
        generate_form,
        alter_state,
        unlimited_lookups,
    ];
    for p in &permissions {
        memory.add_permission(&roles[3], &p).unwrap();
    }
    (memory, users, roles, permissions)
}

#[test]
fn assign_role() {
    let (mut memory, users, roles, _) = test_environment();

    // Add a role to a user that has no role
    assert_eq!(memory.assign_role(&users[4], &roles[0]), Ok(true));

    // Add a role to a user that already has a role
    assert_eq!(memory.assign_role(&users[1], &roles[3]), Ok(true));

    // Add a role to a user that already has that role
    assert_eq!(memory.assign_role(&users[0], &roles[3]), Ok(false));
}

#[test]
fn unassign_role() {
    let (mut memory, users, roles, _) = test_environment();

    // Remove a role from a user that he doesn't have
    assert_eq!(memory.unassign_role(&users[0], &roles[2]), Ok(false));

    // Remove a role from a user who has said role
    assert_eq!(memory.unassign_role(&users[3], &roles[1]), Ok(true));

    // Remove a role from a user who has no role
    assert_eq!(memory.unassign_role(&users[3], &roles[3]), Ok(false));

    // Remove a role from a user who has no role and was never saved internally
    assert_eq!(memory.unassign_role(&users[4], &roles[0]), Ok(false));
}

#[test]
fn add_permission() {
    let (mut memory, _, roles, permissions) = test_environment();

    let temp_role = MyRole { id: 116 };

    // Add a permission to a role that has no permission
    assert_eq!(memory.add_permission(&temp_role, &permissions[0]), Ok(true));

    // Add a permission to a role that already has a permission
    assert_eq!(memory.add_permission(&roles[1], &permissions[4]), Ok(true));

    // Add a permission to a role that already has that permission
    assert_eq!(memory.add_permission(&roles[1], &permissions[4]), Ok(false));
}

#[test]
fn remove_permission() {
    let (mut memory, _, roles, permissions) = test_environment();

    let temp_role = MyRole { id: 114 };

    // Remove a permission from a role that doesn't have the permission
    assert_eq!(
        memory.remove_permission(&roles[0], &permissions[4]),
        Ok(false)
    );

    // Remove a permission from a role that has said permission
    assert_eq!(
        memory.remove_permission(&roles[1], &permissions[2]),
        Ok(true)
    );

    // Remove a permission from a role that has no permissions
    assert_eq!(
        memory.remove_permission(&roles[1], &permissions[2]),
        Ok(false)
    );

    // Remove a permission from a role that has no permission and was never saved internally
    assert_eq!(
        memory.remove_permission(&temp_role, &permissions[0]),
        Ok(false)
    );
}

#[test]
fn user_has_role() {
    let (memory, users, roles, _) = test_environment();

    // The user only has that role
    assert_eq!(memory.user_has_role(&users[0], &roles[3]), Ok(true));

    // The user has the role and has other roles, too
    assert_eq!(memory.user_has_role(&users[2], &roles[0]), Ok(true));

    // The user doesn't have the role, but has other roles
    assert_eq!(memory.user_has_role(&users[3], &roles[3]), Ok(false));

    // The user has no role
    assert_eq!(memory.user_has_role(&users[4], &roles[2]), Ok(false));
}

#[test]
fn role_has_permission() {
    let (memory, _, roles, permissions) = test_environment();

    let temp_role = MyRole { id: 114 };

    // The role only has that permission
    assert_eq!(
        memory.role_has_permission(&roles[1], &permissions[2]),
        Ok(true)
    );

    // The role has the permission and has other permissions, too
    assert_eq!(
        memory.role_has_permission(&roles[2], &permissions[1]),
        Ok(true)
    );

    // The role doesn't have the permission, but has other permissions
    assert_eq!(
        memory.role_has_permission(&roles[2], &permissions[4]),
        Ok(false)
    );

    // The role has no permissions
    assert_eq!(
        memory.role_has_permission(&temp_role, &permissions[3]),
        Ok(false)
    );
}

#[test]
fn user_has_permission() {
    let (mut memory, users, _, permissions) = test_environment();

    // The user has the permission
    // * He only has one role
    //   * The role only has that permission
    assert_eq!(
        memory.user_has_permission(&users[3], &permissions[2]),
        Ok(true)
    );

    //   * The role has multiple permissions
    assert_eq!(
        memory.user_has_permission(&users[1], &permissions[2]),
        Ok(true)
    );

    // * He has multiple roles
    //   * He has the permission in only one role
    //     * The role only has that permission
    assert_eq!(
        memory.user_has_permission(&users[2], &permissions[2]),
        Ok(true)
    );

    //     * The role has multiple permissions
    assert_eq!(
        memory.user_has_permission(&users[2], &permissions[1]),
        Ok(true)
    );

    //   * He has the permission in multiple roles
    //     * The roles only have that permission
    let temp_role = MyRole { id: 114 };
    memory.add_permission(&temp_role, &permissions[2]).unwrap();
    assert_eq!(
        memory.user_has_permission(&users[2], &permissions[2]),
        Ok(true)
    );

    //     * The roles have multiple permissions
    memory.add_permission(&temp_role, &permissions[1]).unwrap();
    assert_eq!(
        memory.user_has_permission(&users[2], &permissions[1]),
        Ok(true)
    );

    // The user doesn't have the permission
    // * He has one role
    assert_eq!(
        memory.user_has_permission(&users[1], &permissions[4]),
        Ok(false)
    );

    // * He has multiple roles
    assert_eq!(
        memory.user_has_permission(&users[2], &permissions[3]),
        Ok(false)
    );

    // * The user has no role
    let temp_user = MyUser { id: 15 };
    assert_eq!(
        memory.user_has_permission(&temp_user, &permissions[3]),
        Ok(false)
    );
}

#[test]
fn iter_user_role_ids() {
    let (memory, users, roles, _) = test_environment();

    // The user has no role
    assert_eq!(
        memory.iter_user_role_ids(&users[4]).unwrap_err(),
        InMemoryRbacError::UserHasNoRoles
    );

    // The user has one role
    let mut iter = memory.iter_user_role_ids(&users[1]).unwrap();
    assert_eq!(iter.next(), Some(roles[2].get_rbac_id()));
    assert_eq!(iter.next(), None);

    // The user has multiple roles
    let role: HashSet<_> = memory.iter_user_role_ids(&users[2]).unwrap().collect();
    assert_eq!(
        role,
        vec![roles[0].get_rbac_id(), roles[1].get_rbac_id()]
            .into_iter()
            .collect()
    );
}

#[test]
fn iter_role_permission_ids() {
    let (memory, _, roles, permissions) = test_environment();

    // The role has no permissions
    let temp_role = MyRole { id: 114 };
    assert_eq!(
        memory.iter_role_permission_ids(&temp_role).unwrap_err(),
        InMemoryRbacError::RoleHasNoPermissions
    );

    // The role has one permission
    let mut iter = memory.iter_role_permission_ids(&roles[1]).unwrap();
    assert_eq!(iter.next(), Some(permissions[2].get_rbac_id()));
    assert_eq!(iter.next(), None);

    // The role has multiple permissions
    let permission: HashSet<_> = memory
        .iter_role_permission_ids(&roles[0])
        .unwrap()
        .collect();
    assert_eq!(
        permission,
        vec![permissions[0].get_rbac_id(), permissions[1].get_rbac_id()]
            .into_iter()
            .collect()
    );
}
