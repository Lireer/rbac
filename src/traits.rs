/// The Identifiable trait needs to be implemented for the types that are used with `RbacModel`
/// and `RbacIterators`.
/// # Examples
/// Implementing Identifiable for your type:
///
/// ```
/// use rbac::traits::Identifiable;
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
    /// # use rbac::traits::Identifiable;
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
/// Implementing RbacIterators for your type:
///
/// ```
/// # use std::hash::Hash;
/// # use std::collections::{HashMap, HashSet};
/// #
/// # use rbac::traits::Identifiable;
/// # use rbac::InMemoryRbacError;
/// # use rbac::traits::RbacIterators;
/// #
/// # pub struct InMemoryRbac<U: Identifiable, R: Identifiable, P: Identifiable>
/// # where
/// #     U::Id: Eq + Hash,
/// #     R::Id: Eq + Hash,
/// #     P::Id: Eq + Hash,
/// # {
/// #     user_role_map: HashMap<U::Id, HashSet<R::Id>>,
/// #     role_permisson_map: HashMap<R::Id, HashSet<P::Id>>,
/// # }
/// #
/// impl<'a, U, R, P> RbacIterators<U, R, P> for &'a InMemoryRbac<U, R, P>
/// where
///     U: Identifiable,
///     U::Id: Eq + Hash,
///     R: Identifiable,
///     R::Id: Eq + Hash + Clone,
///     P: Identifiable,
///     P::Id: Eq + Hash + Clone,
/// {
///     type UserRoles = std::iter::Cloned<std::collections::hash_set::Iter<'a, R::Id>>;
///     type RolePermissions = std::iter::Cloned<std::collections::hash_set::Iter<'a, P::Id>>;
///     type Error = InMemoryRbacError;
///
///     fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRoles, Self::Error> {
///         match self.user_role_map.get(&user.get_rbac_id()) {
///             Some(val) => Ok(val.iter().cloned()),
///             None => Err(InMemoryRbacError::UserHasNoRoles),
///         }
///     }
///
///     fn iter_role_permission_ids(
///         self,
///         role: &R,
///     ) -> Result<Self::RolePermissions, Self::Error> {
///         match self.role_permisson_map.get(&role.get_rbac_id()) {
///             Some(val) => Ok(val.iter().cloned()),
///             None => Err(InMemoryRbacError::RoleHasNoPermissions),
///         }
///     }
/// }
/// ```
pub trait RbacIterators<U, R, P>
where
    U: Identifiable,
    R: Identifiable,
    P: Identifiable,
{
    /// The type of the errors that can happen when using this trait.
    type Error;
    /// The type of the iterator containing the roles of a user.
    type UserRoles: Iterator<Item = R::Id>;
    /// The type of the iterator containing the permissions of a role.
    type RolePermissions: Iterator<Item = P::Id>;

    /// Creates an iterator over the `Id`s of the roles of a user.
    ///
    /// If an error occurs, possibly because of a connection problem to a database,
    /// `Self::Error` is returned in the result.
    fn iter_user_role_ids(self, user: &U) -> Result<Self::UserRoles, Self::Error>;

    /// Creates an iterator over the `Id`s of the permissions of a role.
    ///
    /// If an error occurs, possibly because of a connection problem to a database,
    /// `Self::Error` is returned in the result.
    fn iter_role_permission_ids(self, role: &R) -> Result<Self::RolePermissions, Self::Error>;
}

pub trait RbacStore<U, R, P>
where
    U: Identifiable,
    R: Identifiable,
    P: Identifiable,
{
    type Error;

    /// Add a user without roles to the rbac store.
    fn add_user(&mut self, user: &U) -> Result<bool, Self::Error>;
    /// Remove a user from the rbac store.
    fn remove_user(&mut self, user: &U) -> Result<bool, Self::Error>;
    /// Add a role to a user.
    fn add_user_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error>;
    /// Remove a role from a user.
    fn remove_user_role(&mut self, user: &U, role: &R) -> Result<bool, Self::Error>;

    /// Add a role without permissions to the rbac store.
    fn add_role(&mut self, role: &R) -> Result<bool, Self::Error>;
    /// Remove a role from the rbac store and from all users with this role.
    fn remove_role(&mut self, role: &R) -> Result<bool, Self::Error>;
    /// Add a permission to a role.
    fn add_role_perm(&mut self, role: &R, perm: &P) -> Result<bool, Self::Error>;
    /// Remove a permission from a role.
    fn remove_role_perm(&mut self, role: &R, permission: &P) -> Result<bool, Self::Error>;
}

pub trait RbacModel<U, R, P>
where
    for<'a> &'a Self: RbacIterators<U, R, P>,
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
