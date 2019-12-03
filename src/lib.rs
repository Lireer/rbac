// #![warn(missing_docs)]
//! A crate providing role based access control.

pub mod traits;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use traits::{Identifiable, RbacIterators, RbacModel};

pub struct InMemoryRbac<U: Identifiable, R: Identifiable, P: Identifiable>
where
    U::Id: Eq + Hash,
    R::Id: Eq + Hash,
    P::Id: Eq + Hash,
{
    user_role_map: HashMap<U::Id, HashSet<R::Id>>,
    role_permisson_map: HashMap<R::Id, HashSet<P::Id>>,
}

impl<U: Identifiable, R: Identifiable, P: Identifiable> InMemoryRbac<U, R, P>
where
    U::Id: Eq + Hash,
    R::Id: Eq + Hash,
    P::Id: Eq + Hash,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        InMemoryRbac {
            user_role_map: HashMap::new(),
            role_permisson_map: HashMap::new(),
        }
    }
}

impl<'a, U, R, P> RbacIterators<U, R, P> for &'a InMemoryRbac<U, R, P>
where
    U: Identifiable,
    U::Id: Eq + Hash,
    R: Identifiable,
    R::Id: Eq + Hash + Clone,
    P: Identifiable,
    P::Id: Eq + Hash + Clone,
{
    type UserRoles = std::iter::Cloned<std::collections::hash_set::Iter<'a, R::Id>>;
    type RolePermissions = std::iter::Cloned<std::collections::hash_set::Iter<'a, P::Id>>;
    type Error = InMemoryRbacError;

    fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRoles, Self::Error> {
        match self.user_role_map.get(&user.get_rbac_id()) {
            Some(val) => Ok(val.iter().cloned()),
            None => Err(InMemoryRbacError::UserHasNoRoles),
        }
    }

    fn iter_role_permission_ids(self, role: &R) -> Result<Self::RolePermissions, Self::Error> {
        match self.role_permisson_map.get(&role.get_rbac_id()) {
            Some(val) => Ok(val.iter().cloned()),
            None => Err(InMemoryRbacError::RoleHasNoPermissions),
        }
    }
}

impl<U: Identifiable, R: Identifiable, P: Identifiable> RbacModel<U, R, P> for InMemoryRbac<U, R, P>
where
    U::Id: Eq + Hash,
    R::Id: Eq + Hash + Clone,
    P::Id: Eq + Hash + Clone,
{
    type Error = InMemoryRbacError;

    fn assign_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error> {
        let entry = self
            .user_role_map
            .entry(user.get_rbac_id())
            .or_insert_with(HashSet::new);

        Ok(entry.insert(role.get_rbac_id()))
    }

    fn unassign_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error> {
        match self.user_role_map.entry(user.get_rbac_id()) {
            Entry::Occupied(mut val) => {
                let was_present = val.get_mut().remove(&role.get_rbac_id());
                if val.get().is_empty() {
                    val.remove_entry();
                }
                Ok(was_present)
            }
            Entry::Vacant(_) => Ok(false),
        }
    }

    fn add_permission(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error> {
        let entry = self
            .role_permisson_map
            .entry(role.get_rbac_id())
            .or_insert_with(HashSet::new);
        Ok(entry.insert(permission.get_rbac_id()))
    }

    fn remove_permission(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error> {
        match self.role_permisson_map.entry(role.get_rbac_id()) {
            Entry::Occupied(mut val) => {
                let was_present = val.get_mut().remove(&permission.get_rbac_id());
                if val.get().is_empty() {
                    val.remove_entry();
                }
                Ok(was_present)
            }
            Entry::Vacant(_) => Ok(false),
        }
    }

    fn user_has_permission(&self, user: &U, permission: &P) -> Result<bool, Self::Error> {
        match self.user_role_map.get(&user.get_rbac_id()) {
            Some(val) => Ok(val.iter().any(|r| match self.role_permisson_map.get(r) {
                Some(val) => val.contains(&permission.get_rbac_id()),
                None => false,
            })),
            None => Ok(false),
        }
    }
}

#[derive(Debug, PartialEq)]
/// Possible errors that can occur when using the `InMemoryRbac` struct.
pub enum InMemoryRbacError {
    /// A user has no roles, not even one.
    UserHasNoRoles,
    /// A role has no permissions, not even one.
    RoleHasNoPermissions,
}
