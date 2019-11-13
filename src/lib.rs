// #![warn(missing_docs)]
//! A crate providing role based access control.

use std::hash::Hash;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;

/// The Identifiable trait needs to be implemented for the types that are used with `RbacModel`
/// and `RbacModelIterators`.
/// # Examples
/// Implementing Identifiable for your type:
///
/// ```
/// use rbac::Identifiable;
///
/// struct MyRole {
///     id: u32,
/// }
///
/// impl Identifiable for MyRole {
///     type Id = u32;
///
///     fn get_rbac_id(&self) -> Self::Id {
///         self.id
///     }
/// }
/// ```
pub trait Identifiable {
    /// The type of the id.
    type Id;

    /// Gets the `Id` of `self`.
    /// # Examples
    /// ```
    /// # use rbac::Identifiable;
    /// #
    /// # struct MyRole {
    /// #     id: u32,
    /// # }
    /// #
    /// # impl Identifiable for MyRole {
    /// #     type Id = u32;
    /// #
    /// #     fn get_rbac_id(&self) -> Self::Id {
    /// #        self.id
    /// #     }
    /// # }
    /// #
    /// let role = MyRole{ id: 2 };
    ///
    /// assert_eq!(role.get_rbac_id(), 2);
    /// ```
    fn get_rbac_id(&self) -> Self::Id;
}

/// A trait for providing methods for iterating over roles and permissions.
/// # Example
/// Implementing RbacModelIterators for your type:
/// 
/// ```
/// # use std::hash::Hash;
/// # use std::collections::{HashMap, HashSet};
/// #
/// # use rbac::Identifiable;
/// # use rbac::InMemoryRbacError;
/// # use rbac::RbacModelIterators;
/// #
/// # pub struct InMemoryRbac<U: Identifiable, R: Identifiable, P: Identifiable>
/// # where
/// #     U::Id: Eq + Hash,
/// #     R::Id: Eq + Hash,
/// #     P::Id: Eq + Hash,
/// # {
/// #     data_user_roles: HashMap<U::Id, HashSet<R::Id>>,
/// #     data_role_permissions: HashMap<R::Id, HashSet<P::Id>>,
/// # }
/// #
/// impl<'a, U, R, P> RbacModelIterators<U, R, P> for &'a InMemoryRbac<U, R, P>
/// where
///     U: Identifiable,
///     U::Id: Eq + Hash,
///     R: Identifiable,
///     R::Id: Eq + Hash + Clone,
///     P: Identifiable,
///     P::Id: Eq + Hash + Clone,
/// {
///     type UserRolesIterator = std::iter::Cloned<std::collections::hash_set::Iter<'a, R::Id>>;
///     type RolePermissionsIterator = std::iter::Cloned<std::collections::hash_set::Iter<'a, P::Id>>;
///     type Error = InMemoryRbacError;
/// 
///     fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRolesIterator, Self::Error> {
///         match self.data_user_roles.get(&user.get_rbac_id()) {
///             Some(val) => Ok(val.iter().cloned()),
///             None => Err(InMemoryRbacError::UserHasNoRoles),
///         }
///     }
/// 
///     fn iter_role_permission_ids(
///         self,
///         role: &R,
///     ) -> Result<Self::RolePermissionsIterator, Self::Error> {
///         match self.data_role_permissions.get(&role.get_rbac_id()) {
///             Some(val) => Ok(val.iter().cloned()),
///             None => Err(InMemoryRbacError::RoleHasNoPermissions),
///         }
///     }
/// }
/// ```
pub trait RbacModelIterators<U, R, P>
where
    U: Identifiable,
    R: Identifiable,
    P: Identifiable,
{
    /// The type of the errors that can happen when using this trait.
    type Error;
    /// The type of the iterator containing the roles of a user.
    type UserRolesIterator: Iterator<Item = R::Id>;
    /// The type of the iterator containing the permissions of a role.
    type RolePermissionsIterator: Iterator<Item = P::Id>;

    /// Creates an iterator over the `Id`s of the roles of a user.
    ///
    /// If an error occurs, possibly because of a connection problem to a database,
    /// `Self::Error` is returned in the result.
    fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRolesIterator, Self::Error>;

    /// Creates an iterator over the `Id`s of the permissions of a role.
    ///
    /// If an error occurs, possibly because of a connection problem to a database,
    /// `Self::Error` is returned in the result.
    fn iter_role_permission_ids(
        self,
        role: &R,
    ) -> Result<Self::RolePermissionsIterator, Self::Error>;
}

pub trait RbacModel<U, R, P>
where
    for<'a> &'a Self: RbacModelIterators<U, R, P>,
    U: Identifiable,
    R: Identifiable,
    R::Id: Eq,
    P: Identifiable,
    P::Id: Eq,
{
    type Error;

    fn assign_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error>;
    fn unassign_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error>;
    fn add_permission(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error>;
    fn remove_permission(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error>;
    fn user_has_role(&self, user: &U, role: &R) -> Result<bool, Self::Error> {
        match self.iter_user_role_ids(user) {
            Ok(mut val) => Ok(val.any(|r| r == role.get_rbac_id())),
            Err(_) => Ok(false),
        }
    }
    fn role_has_permission(&self, role: &R, permission: &P) -> Result<bool, Self::Error> {
        match self.iter_role_permission_ids(role) {
            Ok(mut val) => Ok(val.any(|p| p == permission.get_rbac_id())),
            Err(_) => Ok(false),
        }
    }
    fn user_has_permission(&self, user: &U, permission: &P) -> Result<bool, Self::Error>;
}

pub struct InMemoryRbac<U: Identifiable, R: Identifiable, P: Identifiable>
where
    U::Id: Eq + Hash,
    R::Id: Eq + Hash,
    P::Id: Eq + Hash,
{
    data_user_roles: HashMap<U::Id, HashSet<R::Id>>,
    data_role_permissions: HashMap<R::Id, HashSet<P::Id>>,
}

impl<U: Identifiable, R: Identifiable, P: Identifiable> InMemoryRbac<U, R, P>
where
    U::Id: Eq + Hash,
    R::Id: Eq + Hash,
    P::Id: Eq + Hash,
{
    pub fn new() -> Self {
        InMemoryRbac {
            data_user_roles: HashMap::new(),
            data_role_permissions: HashMap::new(),
        }
    }
}

impl<'a, U, R, P> RbacModelIterators<U, R, P> for &'a InMemoryRbac<U, R, P>
where
    U: Identifiable,
    U::Id: Eq + Hash,
    R: Identifiable,
    R::Id: Eq + Hash + Clone,
    P: Identifiable,
    P::Id: Eq + Hash + Clone,
{
    type UserRolesIterator = std::iter::Cloned<std::collections::hash_set::Iter<'a, R::Id>>;
    type RolePermissionsIterator = std::iter::Cloned<std::collections::hash_set::Iter<'a, P::Id>>;
    type Error = InMemoryRbacError;

    fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRolesIterator, Self::Error> {
        match self.data_user_roles.get(&user.get_rbac_id()) {
            Some(val) => Ok(val.iter().cloned()),
            None => Err(InMemoryRbacError::UserHasNoRoles),
        }
    }

    fn iter_role_permission_ids(
        self,
        role: &R,
    ) -> Result<Self::RolePermissionsIterator, Self::Error> {
        match self.data_role_permissions.get(&role.get_rbac_id()) {
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
        let entry = self.data_user_roles.entry(user.get_rbac_id()).or_insert_with(HashSet::new);

        Ok(entry.insert(role.get_rbac_id()))
    }

    fn unassign_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error> {
        match self.data_user_roles.entry(user.get_rbac_id()) {
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
        let entry = self.data_role_permissions.entry(role.get_rbac_id())
                                                         .or_insert_with(HashSet::new);
        Ok(entry.insert(permission.get_rbac_id()))
    }

    fn remove_permission(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error> {
        match self.data_role_permissions.entry(role.get_rbac_id()) {
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
        match self.data_user_roles.get(&user.get_rbac_id()) {
            Some(val) => Ok(
                val.iter().any(|r| match self.data_role_permissions.get(r) {
                    Some(val) => val.contains(&permission.get_rbac_id()),
                    None => false
                })
            ),
            None => Ok(false)
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
