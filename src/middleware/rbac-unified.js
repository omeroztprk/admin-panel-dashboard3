function hasPermission(requiredPermission) {
  return (req, res, next) => {
    if (!req.user?.permissions) {
      return res.status(403).json({ message: 'No permissions found' });
    }

    const userPermissions = req.user.permissions.map(p => {
      if (typeof p === 'string') return p;
      return p.name || `${p.resource}:${p.action}`;
    }).filter(Boolean);

    if (checkPermission(userPermissions, requiredPermission)) {
      return next();
    }

    return res.status(403).json({
      message: 'Insufficient permissions',
      required: requiredPermission
    });
  };
}

function hasAnyPermission(requiredPermissions) {
  return (req, res, next) => {
    if (!req.user?.permissions) {
      return res.status(403).json({ message: 'No permissions found' });
    }

    const userPermissions = req.user.permissions.map(p => {
      if (typeof p === 'string') return p;
      return p.name || `${p.resource}:${p.action}`;
    }).filter(Boolean);

    const hasAccess = requiredPermissions.some(perm => checkPermission(userPermissions, perm));
    if (hasAccess) {
      return next();
    }

    return res.status(403).json({
      message: 'Insufficient permissions',
      required: requiredPermissions
    });
  };
}

function isSelfOrHasPermission(requiredPermission) {
  return (req, res, next) => {
    const targetUserId = req.params.id;
    const currentUserId = req.user?._id?.toString() || req.user?.id?.toString();

    if (targetUserId === currentUserId) {
      return next();
    }

    return hasPermission(requiredPermission)(req, res, next);
  };
}

function checkPermission(userPermissions, required) {
  if (!userPermissions || !required) return false;

  if (userPermissions.includes(required)) return true;

  if (userPermissions.includes('*:*')) return true;

  const [resource, action] = required.split(':');
  if (!resource || !action) return false;

  if (userPermissions.includes(`${resource}:*`)) return true;

  if (userPermissions.includes(`*:${action}`)) return true;

  if (userPermissions.includes(`${resource}:manage`)) {
    const managedActions = ['create', 'read', 'update', 'delete'];
    if (managedActions.includes(action)) return true;
  }

  return false;
}

module.exports = {
  hasPermission,
  hasAnyPermission,
  isSelfOrHasPermission,
  checkPermission
};