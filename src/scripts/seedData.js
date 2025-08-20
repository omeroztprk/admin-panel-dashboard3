require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const Category = require('../models/Category');
const {
  ROLES, PERMISSIONS, PERMISSION_CATEGORIES, RESOURCES, ACTIONS
} = require('../utils/constants');

const ADMIN_EMAIL = process.env.SEED_ADMIN_EMAIL || 'admin@admin.com';
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD || 'Admin123!';

// ═══════════════════════════════════════════════════════════════════════════════
// 🔧 CORE SYSTEM FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is required');
  }

  const maxRetries = 3;
  let retryCount = 0;

  while (retryCount < maxRetries) {
    try {
      await mongoose.connect(uri, {
        maxPoolSize: 10,
        minPoolSize: 1,
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS: 45000,
      });
      console.log('✅ Database connected successfully');
      return;
    } catch (error) {
      retryCount++;
      console.error(`❌ Database connection attempt ${retryCount} failed:`, error.message);
      if (retryCount >= maxRetries) throw error;
      await new Promise(resolve => setTimeout(resolve, 2000 * retryCount));
    }
  }
};

const clearExistingData = async (options = {}) => {
  const { preserveSystemData = true, preserveSuperAdmin = true } = options;

  try {
    console.log('🧹 Clearing existing data...');

    if (!preserveSystemData) {
      await Permission.deleteMany({});
      await Role.deleteMany({});
      await Category.deleteMany({});
      console.log('   🗑️  All system data cleared');
    } else {
      await Permission.deleteMany({ isSystem: { $ne: true } });
      await Role.deleteMany({ isSystem: { $ne: true } });
      await Category.deleteMany({ isSystem: { $ne: true } });
      console.log('   🗑️  Non-system data cleared');
    }

    if (!preserveSuperAdmin) {
      await User.deleteMany({});
      console.log('   🗑️  All users cleared');
    } else {
      const superAdminRole = await Role.findOne({ name: ROLES.SUPER_ADMIN });
      if (superAdminRole) {
        await User.deleteMany({ roles: { $ne: superAdminRole._id } });
        console.log('   🗑️  Non-super-admin users cleared');
      } else {
        await User.deleteMany({});
        console.log('   🗑️  All users cleared (no super admin role found)');
      }
    }

    console.log('🧹 Data clearing completed');
  } catch (error) {
    console.error('❌ Error clearing data:', error.message);
    throw error;
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🔑 COMPREHENSIVE PERMISSION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

const createPermissions = async () => {
  console.log('📋 Creating comprehensive permission system...');

  const permissions = [
    // User Management Permissions
    { name: PERMISSIONS.USER_READ, displayName: 'View Users', description: 'View user information, profiles, and account details', resource: RESOURCES.USER, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_CREATE, displayName: 'Create Users', description: 'Create new user accounts and manage user onboarding', resource: RESOURCES.USER, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_UPDATE, displayName: 'Update Users', description: 'Edit user information, profiles, and account settings', resource: RESOURCES.USER, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_DELETE, displayName: 'Delete Users', description: 'Delete user accounts and manage user offboarding', resource: RESOURCES.USER, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_MANAGE, displayName: 'Manage Users', description: 'Full user management including roles, permissions, status changes', resource: RESOURCES.USER, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },

    // Role Management Permissions
    { name: PERMISSIONS.ROLE_READ, displayName: 'View Roles', description: 'View role information, permissions, and hierarchy', resource: RESOURCES.ROLE, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_CREATE, displayName: 'Create Roles', description: 'Create new roles for access control', resource: RESOURCES.ROLE, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_UPDATE, displayName: 'Update Roles', description: 'Edit role information, permissions, and assignments', resource: RESOURCES.ROLE, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_DELETE, displayName: 'Delete Roles', description: 'Delete roles and manage role lifecycle', resource: RESOURCES.ROLE, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_MANAGE, displayName: 'Manage Roles', description: 'Full role management including permission assignments', resource: RESOURCES.ROLE, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },

    // Permission Management Permissions
    { name: PERMISSIONS.PERMISSION_READ, displayName: 'View Permissions', description: 'View permission information and categories', resource: RESOURCES.PERMISSION, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_CREATE, displayName: 'Create Permissions', description: 'Create new permissions for system resources', resource: RESOURCES.PERMISSION, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_UPDATE, displayName: 'Update Permissions', description: 'Edit permission information and properties', resource: RESOURCES.PERMISSION, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_DELETE, displayName: 'Delete Permissions', description: 'Delete permissions from the system', resource: RESOURCES.PERMISSION, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_MANAGE, displayName: 'Manage Permissions', description: 'Full permission management including status changes', resource: RESOURCES.PERMISSION, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },

    // Audit Management Permissions
    { name: PERMISSIONS.AUDIT_READ, displayName: 'View Audit Logs', description: 'View system audit logs, security events, and user activities', resource: RESOURCES.AUDIT, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.AUDIT_MANAGEMENT },

    // Category Management Permissions
    { name: PERMISSIONS.CATEGORY_READ, displayName: 'View Categories', description: 'View categories and their hierarchy structure', resource: RESOURCES.CATEGORY, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_CREATE, displayName: 'Create Categories', description: 'Create new categories and organize content', resource: RESOURCES.CATEGORY, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_UPDATE, displayName: 'Update Categories', description: 'Edit category details, descriptions, and hierarchy', resource: RESOURCES.CATEGORY, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_DELETE, displayName: 'Delete Categories', description: 'Delete categories and manage category lifecycle', resource: RESOURCES.CATEGORY, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_MANAGE, displayName: 'Manage Categories', description: 'Full category management including moving, ordering, and status changes', resource: RESOURCES.CATEGORY, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
  ];

  let upserted = 0;
  const permissionMap = new Map();

  console.log(`   📝 Processing ${permissions.length} permissions (upsert)...`);

  for (const p of permissions) {
    try {
      const existing = await Permission.findOne({ name: p.name });
      if (existing) {
        // Update existing permission (non-system fields only)
        if (!existing.isSystem) {
          await Permission.findByIdAndUpdate(existing._id, {
            displayName: p.displayName,
            description: p.description,
            resource: p.resource,
            action: p.action,
            category: p.category,
            isActive: true
          });
          upserted++;
        }
        permissionMap.set(p.name, existing);
      } else {
        // Create new permission
        const newPermission = await Permission.create({
          ...p,
          isSystem: true,
          isActive: true
        });
        permissionMap.set(p.name, newPermission);
        upserted++;
      }
    } catch (error) {
      console.error(`   ❌ Failed to create/update permission ${p.name}:`, error.message);
    }
  }

  console.log(`📋 Permission system ready: ${upserted} permissions upserted`);
  return permissionMap;
};

// ═══════════════════════════════════════════════════════════════════════════════
// 👥 ROLE HIERARCHY
// ═══════════════════════════════════════════════════════════════════════════════

const createRoles = async (permissionMap) => {
  console.log('👥 Creating role hierarchy...');

  const roleDefinitions = [
    {
      name: ROLES.SUPER_ADMIN,
      displayName: 'Super Administrator',
      description: 'Complete system access with all permissions',
      priority: 100,
      permissions: Array.from(permissionMap.values()).map(p => p._id),
      isSystem: true
    },
    {
      name: ROLES.ADMIN,
      displayName: 'Administrator',
      description: 'Administrative access with most management permissions',
      priority: 80,
      permissions: [
        PERMISSIONS.USER_READ,
        PERMISSIONS.USER_CREATE,
        PERMISSIONS.USER_UPDATE,
        PERMISSIONS.USER_MANAGE,
        PERMISSIONS.ROLE_READ,
        PERMISSIONS.ROLE_CREATE,
        PERMISSIONS.ROLE_UPDATE,
        PERMISSIONS.PERMISSION_READ,
        PERMISSIONS.AUDIT_READ,
        PERMISSIONS.CATEGORY_READ,
        PERMISSIONS.CATEGORY_CREATE,
        PERMISSIONS.CATEGORY_UPDATE,
        PERMISSIONS.CATEGORY_MANAGE,
      ].map(pName => permissionMap.get(pName)?._id).filter(Boolean),
      isSystem: true
    },
    {
      name: ROLES.MODERATOR,
      displayName: 'Moderator',
      description: 'Content and user moderation capabilities',
      priority: 60,
      permissions: [
        PERMISSIONS.USER_READ,
        PERMISSIONS.USER_UPDATE,
        PERMISSIONS.ROLE_READ,
        PERMISSIONS.PERMISSION_READ,
        PERMISSIONS.AUDIT_READ,
        PERMISSIONS.CATEGORY_READ,
        PERMISSIONS.CATEGORY_CREATE,
        PERMISSIONS.CATEGORY_UPDATE,
      ].map(pName => permissionMap.get(pName)?._id).filter(Boolean),
      isSystem: true
    },
    {
      name: ROLES.USER,
      displayName: 'User',
      description: 'Basic user access with limited permissions',
      priority: 20,
      permissions: [
        PERMISSIONS.CATEGORY_READ,
      ].map(pName => permissionMap.get(pName)?._id).filter(Boolean),
      isSystem: true
    }
  ];

  const roleMap = new Map();
  let created = 0;
  let updated = 0;

  for (const roleDef of roleDefinitions) {
    try {
      const existing = await Role.findOne({ name: roleDef.name });
      
      if (existing) {
        // Update existing role (preserve system status)
        await Role.findByIdAndUpdate(existing._id, {
          displayName: roleDef.displayName,
          description: roleDef.description,
          priority: roleDef.priority,
          permissions: roleDef.permissions,
          isActive: true
        });
        roleMap.set(roleDef.name, existing);
        updated++;
        console.log(`   ✏️  Updated role: ${roleDef.name}`);
      } else {
        // Create new role
        const newRole = await Role.create(roleDef);
        roleMap.set(roleDef.name, newRole);
        created++;
        console.log(`   ➕ Created role: ${roleDef.name}`);
      }
    } catch (error) {
      console.error(`   ❌ Failed to create/update role ${roleDef.name}:`, error.message);
    }
  }

  console.log(`👥 Role hierarchy ready: ${created} created, ${updated} updated`);
  return roleMap;
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🗂️ DEFAULT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

const createDefaultCategories = async () => {
  console.log('🗂️ Creating default categories...');

  const categoryDefinitions = [
    {
      name: 'General',
      slug: 'general',
      description: 'General purpose category for miscellaneous items',
      order: 1,
      isSystem: true
    },
    {
      name: 'System',
      slug: 'system',
      description: 'System-related categories and configurations',
      order: 2,
      isSystem: true
    },
    {
      name: 'Content',
      slug: 'content',
      description: 'Content management and organization',
      order: 3,
      isSystem: false
    }
  ];

  let created = 0;
  let updated = 0;

  for (const catDef of categoryDefinitions) {
    try {
      const existing = await Category.findOne({ slug: catDef.slug, parent: null });
      
      if (existing) {
        if (!existing.isSystem || catDef.isSystem) {
          await Category.findByIdAndUpdate(existing._id, {
            name: catDef.name,
            description: catDef.description,
            order: catDef.order,
            isActive: true,
            path: [],
            fullSlug: catDef.slug,
            level: 0
          });
          updated++;
          console.log(`   ✏️  Updated category: ${catDef.name}`);
        }
      } else {
        await Category.create({
          ...catDef,
          parent: null,
          path: [],
          fullSlug: catDef.slug,
          level: 0,
          isActive: true
        });
        created++;
        console.log(`   ➕ Created category: ${catDef.name}`);
      }
    } catch (error) {
      console.error(`   ❌ Failed to create/update category ${catDef.name}:`, error.message);
    }
  }

  console.log(`🗂️ Default categories ready: ${created} created, ${updated} updated`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// 👤 USER CREATION
// ═══════════════════════════════════════════════════════════════════════════════

const createSuperAdmin = async (roleMap) => {
  console.log('👤 Creating super admin user...');

  const superAdminRole = roleMap.get(ROLES.SUPER_ADMIN);
  if (!superAdminRole) {
    throw new Error('Super Admin role not found');
  }

  try {
    const existing = await User.findOne({ email: ADMIN_EMAIL });
    
    if (existing) {
      // Update existing super admin
      await User.findByIdAndUpdate(existing._id, {
        firstName: 'Super',
        lastName: 'Admin',
        roles: [superAdminRole._id],
        isActive: true,
        isEmailVerified: true,
        profile: {
          language: 'tr',
          timezone: 'UTC'
        }
      });
      console.log(`   ✏️  Updated super admin: ${ADMIN_EMAIL}`);
    } else {
      // Create new super admin
      await User.create({
        firstName: 'Super',
        lastName: 'Admin',
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD,
        roles: [superAdminRole._id],
        isActive: true,
        isEmailVerified: true,
        profile: {
          language: 'tr',
          timezone: 'UTC'
        }
      });
      console.log(`   ➕ Created super admin: ${ADMIN_EMAIL}`);
    }

    console.log('👤 Super admin ready');
  } catch (error) {
    console.error('❌ Failed to create super admin:', error.message);
    throw error;
  }
};

const createTestUsers = async (roleMap) => {
  console.log('👥 Creating test users...');

  const testUsers = [
    {
      firstName: 'Admin',
      lastName: 'User',
      email: 'admin.user@test.com',
      password: 'Admin123!',
      role: ROLES.ADMIN
    },
    {
      firstName: 'Moderator',
      lastName: 'User',
      email: 'moderator.user@test.com',
      password: 'Moderator123!',
      role: ROLES.MODERATOR
    },
    {
      firstName: 'Regular',
      lastName: 'User',
      email: 'regular.user@test.com',
      password: 'User123!',
      role: ROLES.USER
    }
  ];

  let created = 0;
  let updated = 0;

  for (const userData of testUsers) {
    try {
      const role = roleMap.get(userData.role);
      if (!role) {
        console.warn(`   ⚠️  Role ${userData.role} not found for user ${userData.email}`);
        continue;
      }

      const existing = await User.findOne({ email: userData.email });
      
      if (existing) {
        await User.findByIdAndUpdate(existing._id, {
          firstName: userData.firstName,
          lastName: userData.lastName,
          roles: [role._id],
          isActive: true,
          isEmailVerified: true
        });
        updated++;
        console.log(`   ✏️  Updated test user: ${userData.email}`);
      } else {
        await User.create({
          ...userData,
          roles: [role._id],
          isActive: true,
          isEmailVerified: true,
          profile: {
            language: 'tr',
            timezone: 'UTC'
          }
        });
        created++;
        console.log(`   ➕ Created test user: ${userData.email}`);
      }
    } catch (error) {
      console.error(`   ❌ Failed to create/update test user ${userData.email}:`, error.message);
    }
  }

  console.log(`👥 Test users ready: ${created} created, ${updated} updated`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// 📊 SYSTEM VALIDATION & REPORTING
// ═══════════════════════════════════════════════════════════════════════════════

const validateSystemIntegrity = async () => {
  console.log('🔍 Validating system integrity...');

  const issues = [];

  try {
    // Check permissions
    const permissionCount = await Permission.countDocuments({ isActive: true });
    const expectedPermissions = Object.keys(PERMISSIONS).length;
    if (permissionCount < expectedPermissions) {
      issues.push(`Missing permissions: expected ${expectedPermissions}, found ${permissionCount}`);
    }

    // Check roles
    const roleCount = await Role.countDocuments({ isActive: true });
    const expectedRoles = Object.keys(ROLES).length;
    if (roleCount < expectedRoles) {
      issues.push(`Missing roles: expected ${expectedRoles}, found ${roleCount}`);
    }

    // Check super admin
    const superAdminRole = await Role.findOne({ name: ROLES.SUPER_ADMIN });
    if (!superAdminRole) {
      issues.push('Super Admin role not found');
    } else {
      const superAdminUser = await User.findOne({ roles: superAdminRole._id });
      if (!superAdminUser) {
        issues.push('Super Admin user not found');
      }
    }

    // Check role permissions
    for (const roleName of Object.values(ROLES)) {
      const role = await Role.findOne({ name: roleName }).populate('permissions');
      if (role && role.permissions.length === 0 && roleName !== ROLES.USER) {
        issues.push(`Role ${roleName} has no permissions assigned`);
      }
    }

    if (issues.length === 0) {
      console.log('✅ System integrity validated successfully');
    } else {
      console.warn('⚠️  System integrity issues found:');
      issues.forEach(issue => console.warn(`   - ${issue}`));
    }

    return { valid: issues.length === 0, issues };
  } catch (error) {
    console.error('❌ System validation failed:', error.message);
    return { valid: false, issues: [error.message] };
  }
};

const generateSystemReport = async () => {
  console.log('\n📊 Generating system report...');

  try {
    const [
      userStats,
      roleStats,
      permissionStats,
      categoryStats
    ] = await Promise.all([
      User.aggregate([
        { $group: { _id: '$isActive', count: { $sum: 1 } } },
        { $project: { status: { $cond: ['$_id', 'active', 'inactive'] }, count: 1, _id: 0 } }
      ]),
      Role.aggregate([
        { $group: { _id: '$isActive', count: { $sum: 1 } } },
        { $project: { status: { $cond: ['$_id', 'active', 'inactive'] }, count: 1, _id: 0 } }
      ]),
      Permission.aggregate([
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]),
      Category.aggregate([
        { $group: { _id: '$level', count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ])
    ]);

    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('📈 ADMIN PANEL SYSTEM REPORT');
    console.log('═══════════════════════════════════════════════════════════════');

    console.log('\n👥 USERS:');
    userStats.forEach(stat => console.log(`   ${stat.status}: ${stat.count}`));

    console.log('\n🛡️  ROLES:');
    roleStats.forEach(stat => console.log(`   ${stat.status}: ${stat.count}`));

    console.log('\n🔑 PERMISSIONS BY CATEGORY:');
    permissionStats.forEach(stat => console.log(`   ${stat._id}: ${stat.count}`));

    console.log('\n🗂️ CATEGORIES BY LEVEL:');
    categoryStats.forEach(stat => console.log(`   Level ${stat._id}: ${stat.count}`));

    const totalUsers = await User.countDocuments();
    const totalRoles = await Role.countDocuments();
    const totalPermissions = await Permission.countDocuments();
    const totalCategories = await Category.countDocuments();

    console.log('\n📊 TOTALS:');
    console.log(`   Users: ${totalUsers}`);
    console.log(`   Roles: ${totalRoles}`);
    console.log(`   Permissions: ${totalPermissions}`);
    console.log(`   Categories: ${totalCategories}`);

    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('✅ System seeding completed successfully!');
    console.log('═══════════════════════════════════════════════════════════════\n');

  } catch (error) {
    console.error('❌ Failed to generate system report:', error.message);
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🚀 MAIN SEEDING ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

const safeExit = async (code) => {
  try {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close();
      console.log('💾 Database connection closed');
    }
  } catch (error) {
    console.error('❌ Error closing database connection:', error.message);
  } finally {
    process.exit(code);
  }
};

const seedData = async (options = {}) => {
  const {
    clearData = false,
    preserveSystemData = true,
    preserveSuperAdmin = true,
    createTestData = true,
    validateIntegrity = true
  } = options;

  console.log('🌱 Starting admin panel data seeding...');
  console.log(`📋 Options: clearData=${clearData}, preserveSystemData=${preserveSystemData}, createTestData=${createTestData}`);

  try {
    // 1. Database Connection
    await connectDB();

    // 2. Clear existing data if requested
    if (clearData) {
      await clearExistingData({ preserveSystemData, preserveSuperAdmin });
    }

    // 3. Create permissions (foundation)
    const permissionMap = await createPermissions();

    // 4. Create roles (depends on permissions)
    const roleMap = await createRoles(permissionMap);

    // 5. Create default categories
    await createDefaultCategories();

    // 6. Create super admin user
    await createSuperAdmin(roleMap);

    // 7. Create test users if requested
    if (createTestData) {
      await createTestUsers(roleMap);
    }

    // 8. Validate system integrity
    if (validateIntegrity) {
      await validateSystemIntegrity();
    }

    // 9. Generate final report
    await generateSystemReport();

    return { success: true, message: 'Seeding completed successfully' };

  } catch (error) {
    console.error('💥 Fatal error during seeding:', error.message);
    console.error(error.stack);
    return { success: false, message: error.message };
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🎯 EXECUTION & EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {
    clearData: args.includes('--clear') || args.includes('-c'),
    preserveSystemData: !args.includes('--clear-all'),
    preserveSuperAdmin: !args.includes('--clear-all'),
    createTestData: !args.includes('--no-test-data'),
    validateIntegrity: !args.includes('--no-validate')
  };

  seedData(options)
    .then(result => {
      console.log(result.success ? '✅ Seeding completed!' : `❌ Seeding failed: ${result.message}`);
      safeExit(result.success ? 0 : 1);
    })
    .catch(error => {
      console.error('💥 Unhandled error:', error.message);
      safeExit(1);
    });
}

module.exports = {
  seedData,
  createPermissions,
  createRoles,
  createSuperAdmin,
  createTestUsers,
  validateSystemIntegrity,
  generateSystemReport,
};