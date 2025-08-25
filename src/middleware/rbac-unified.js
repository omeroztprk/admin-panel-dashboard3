function hasPermission(requiredPermission) {
  return (req, res, next) => {
    if (!req.user?.permissions) {
      return res.status(403).json({ message: 'No permissions found' });
    }

    // permissions array'inden permission name'leri çıkar
    const userPermissions = req.user.permissions.map(p => {
      if (typeof p === 'string') return p;
      return p.name || `${p.resource}:${p.action}`;
    }).filter(Boolean);
    
    if (checkPermission(userPermissions, requiredPermission)) {
      return next();
    }

    return res.status(403).json({ 
      message: 'Insufficient permissions',
      required: requiredPermission,
      userPermissions: userPermissions // Debug için
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
      required: requiredPermissions,
      userPermissions: userPermissions
    });
  };
}

function isSelfOrHasPermission(requiredPermission) {
  return (req, res, next) => {
    const targetUserId = req.params.id;
    const currentUserId = req.user?._id?.toString() || req.user?.id?.toString();
    
    // Kendi kaydına erişim
    if (targetUserId === currentUserId) {
      return next();
    }

    // İzin kontrolü
    return hasPermission(requiredPermission)(req, res, next);
  };
}

function checkPermission(userPermissions, required) {
  if (!userPermissions || !required) return false;
  
  // Tam eşleşme
  if (userPermissions.includes(required)) return true;
  
  // Super admin
  if (userPermissions.includes('*:*')) return true;
  
  const [resource, action] = required.split(':');
  if (!resource || !action) return false;
  
  // Resource bazlı wildcard
  if (userPermissions.includes(`${resource}:*`)) return true;
  
  // Action bazlı wildcard  
  if (userPermissions.includes(`*:${action}`)) return true;
  
  // Manage permission (create, read, update, delete içerir)
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