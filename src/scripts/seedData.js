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
    console.error('❌ MONGODB_URI not set');
    process.exit(1);
  }

  const maxRetries = 3;
  let retryCount = 0;

  while (retryCount < maxRetries) {
    try {
      await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
      console.log('✅ MongoDB connected for seeding...');
      return;
    } catch (error) {
      retryCount++;
      console.error(`❌ MongoDB connection attempt ${retryCount}/${maxRetries} failed:`, error.message);

      if (retryCount === maxRetries) {
        console.error('💀 Failed to connect to MongoDB after all retries');
        process.exit(1);
      }

      console.log('⏳ Retrying in 3 seconds...');
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
};

const clearExistingData = async (options = {}) => {
  const { preserveSystemData = true, preserveSuperAdmin = true } = options;

  try {
    console.log('🧹 Clearing existing data...');

    if (preserveSystemData) {
      await Permission.deleteMany({ isSystem: { $ne: true } });
      await Role.deleteMany({ isSystem: { $ne: true } });
      await Category.deleteMany({ isSystem: { $ne: true } });

      if (preserveSuperAdmin) {
        await User.deleteMany({ email: { $ne: ADMIN_EMAIL } });
      } else {
        await User.deleteMany({});
      }
    } else {
      await Permission.deleteMany({});
      await Role.deleteMany({});
      await Category.deleteMany({});
      await User.deleteMany({});
    }

    console.log('   ✅ Data cleanup completed');
  } catch (error) {
    console.error('   ❌ Error during cleanup:', error.message);
    throw error;
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🔑 COMPREHENSIVE PERMISSION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

const createPermissions = async () => {
  console.log('📋 Creating comprehensive permission system...');

  const permissions = [
    // 👤 USER MANAGEMENT
    { name: PERMISSIONS.USER_READ, displayName: 'View Users', description: 'View user information, profiles, and account details', resource: RESOURCES.USER, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_CREATE, displayName: 'Create Users', description: 'Create new user accounts and manage user onboarding', resource: RESOURCES.USER, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_UPDATE, displayName: 'Update Users', description: 'Edit user information, profiles, and account settings', resource: RESOURCES.USER, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_DELETE, displayName: 'Delete Users', description: 'Delete user accounts and manage user offboarding', resource: RESOURCES.USER, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_MANAGE, displayName: 'Manage Users', description: 'Full user management including roles, permissions', resource: RESOURCES.USER, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },
    { name: PERMISSIONS.USER_UNLOCK, displayName: 'Unlock Users', description: 'Unlock locked user accounts and reset security flags', resource: RESOURCES.USER, action: ACTIONS.UNLOCK, category: PERMISSION_CATEGORIES.USER_MANAGEMENT },

    // 🛡️ ROLE MANAGEMENT
    { name: PERMISSIONS.ROLE_READ, displayName: 'View Roles', description: 'View role information, permissions, and hierarchy', resource: RESOURCES.ROLE, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_CREATE, displayName: 'Create Roles', description: 'Create new roles for access control', resource: RESOURCES.ROLE, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_UPDATE, displayName: 'Update Roles', description: 'Edit role information, permissions, and assignments', resource: RESOURCES.ROLE, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_DELETE, displayName: 'Delete Roles', description: 'Delete roles and manage role lifecycle', resource: RESOURCES.ROLE, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },
    { name: PERMISSIONS.ROLE_MANAGE, displayName: 'Manage Roles', description: 'Full role management', resource: RESOURCES.ROLE, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.ROLE_MANAGEMENT },

    // 🔑 PERMISSION MANAGEMENT
    { name: PERMISSIONS.PERMISSION_READ, displayName: 'View Permissions', description: 'View permission information', resource: RESOURCES.PERMISSION, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_CREATE, displayName: 'Create Permissions', description: 'Create new permissions', resource: RESOURCES.PERMISSION, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_UPDATE, displayName: 'Update Permissions', description: 'Edit permission information', resource: RESOURCES.PERMISSION, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_DELETE, displayName: 'Delete Permissions', description: 'Delete permissions', resource: RESOURCES.PERMISSION, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },
    { name: PERMISSIONS.PERMISSION_MANAGE, displayName: 'Manage Permissions', description: 'Full permission management', resource: RESOURCES.PERMISSION, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.PERMISSION_MANAGEMENT },

    // 📊 AUDIT
    { name: PERMISSIONS.AUDIT_READ, displayName: 'View Audit Logs', description: 'View system audit logs', resource: RESOURCES.AUDIT, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.AUDIT_MANAGEMENT },
    { name: PERMISSIONS.AUDIT_EXPORT, displayName: 'Export Audit Logs', description: 'Export audit logs', resource: RESOURCES.AUDIT, action: ACTIONS.EXPORT, category: PERMISSION_CATEGORIES.AUDIT_MANAGEMENT },

    // ⚙️ SYSTEM
    { name: PERMISSIONS.SYSTEM_HEALTH, displayName: 'System Health Monitoring', description: 'Monitor system health', resource: RESOURCES.SYSTEM, action: ACTIONS.HEALTH, category: PERMISSION_CATEGORIES.SYSTEM_MANAGEMENT },

    // 🗂️ CATEGORY MANAGEMENT
    { name: PERMISSIONS.CATEGORY_READ, displayName: 'View Categories', description: 'View categories and their hierarchy', resource: RESOURCES.CATEGORY, action: ACTIONS.READ, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_CREATE, displayName: 'Create Categories', description: 'Create new categories', resource: RESOURCES.CATEGORY, action: ACTIONS.CREATE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_UPDATE, displayName: 'Update Categories', description: 'Edit category details and parent', resource: RESOURCES.CATEGORY, action: ACTIONS.UPDATE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_DELETE, displayName: 'Delete Categories', description: 'Delete categories', resource: RESOURCES.CATEGORY, action: ACTIONS.DELETE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
    { name: PERMISSIONS.CATEGORY_MANAGE, displayName: 'Manage Categories', description: 'Category status/move/ordering', resource: RESOURCES.CATEGORY, action: ACTIONS.MANAGE, category: PERMISSION_CATEGORIES.CATEGORY_MANAGEMENT },
  ];

  let upserted = 0;
  const permissionMap = new Map();

  console.log(`   📝 Processing ${permissions.length} permissions (upsert)...`);

  for (const p of permissions) {
    try {
      const doc = await Permission.findOneAndUpdate(
        { name: p.name },
        {
          $set: {
            displayName: p.displayName,
            description: p.description,
            resource: p.resource,
            action: p.action,
            category: p.category,
            isSystem: true,
            isActive: true,
          }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      permissionMap.set(p.name, doc._id);
      upserted++;
    } catch (error) {
      console.error(`   ❌ Error upserting permission ${p.name}:`, error.message);
    }
  }

  console.log(`📋 Permission system ready: ${upserted} upserted`);
  return permissionMap;
};

// ═══════════════════════════════════════════════════════════════════════════════
// 👥 ROLE HIERARCHY
// ═══════════════════════════════════════════════════════════════════════════════

const createRoles = async (permissionMap) => {
  console.log('👥 Creating role hierarchy...');

  // Get all permissions for Super Admin
  const allPermissions = await Permission.find({ isActive: true }).select('_id name');
  const allPermissionIds = allPermissions.map((p) => p._id);

  // 🌟 SUPER ADMIN - ULTIMATE ACCESS
  const superAdminPermissions = allPermissionIds;

  // 👔 ADMIN - COMPREHENSIVE MANAGEMENT
  const adminPermissionNames = [
    PERMISSIONS.USER_READ, PERMISSIONS.USER_CREATE, PERMISSIONS.USER_UPDATE,
    PERMISSIONS.USER_DELETE, PERMISSIONS.USER_MANAGE, PERMISSIONS.USER_UNLOCK,
    PERMISSIONS.ROLE_READ, PERMISSIONS.ROLE_UPDATE, PERMISSIONS.ROLE_MANAGE,
    PERMISSIONS.PERMISSION_READ,
    PERMISSIONS.AUDIT_READ, PERMISSIONS.AUDIT_EXPORT,
    PERMISSIONS.SYSTEM_HEALTH,
    PERMISSIONS.CATEGORY_READ, PERMISSIONS.CATEGORY_CREATE,
    PERMISSIONS.CATEGORY_UPDATE, PERMISSIONS.CATEGORY_DELETE,
    PERMISSIONS.CATEGORY_MANAGE,
  ];

  // 🛡️ MODERATOR - LIMITED ADMINISTRATIVE ACCESS
  const moderatorPermissionNames = [
    PERMISSIONS.USER_READ, PERMISSIONS.USER_UPDATE, PERMISSIONS.USER_UNLOCK,
    PERMISSIONS.ROLE_READ,
    PERMISSIONS.PERMISSION_READ,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.SYSTEM_HEALTH,
    PERMISSIONS.CATEGORY_READ, PERMISSIONS.CATEGORY_UPDATE, PERMISSIONS.CATEGORY_MANAGE,
  ];

  // 👤 USER - BASIC ACCESS
  const userPermissionNames = [];

  const getPermissionIds = (permissionNames) =>
    permissionNames.map((name) => permissionMap.get(name)).filter((id) => id !== undefined);

  const roles = [
    {
      name: ROLES.SUPER_ADMIN,
      displayName: 'Super Administrator',
      description: 'Ultimate system access with all permissions for system administration',
      priority: 100,
      isSystem: true,
      isActive: true,
      permissions: superAdminPermissions,
    },
    {
      name: ROLES.ADMIN,
      displayName: 'Administrator',
      description: 'Comprehensive administrative access for user and system management',
      priority: 80,
      isSystem: true,
      isActive: true,
      permissions: getPermissionIds(adminPermissionNames),
    },
    {
      name: ROLES.MODERATOR,
      displayName: 'Moderator',
      description: 'Limited administrative access for content and user moderation',
      priority: 60,
      isSystem: true,
      isActive: true,
      permissions: getPermissionIds(moderatorPermissionNames),
    },
    {
      name: ROLES.USER,
      displayName: 'User',
      description: 'Standard user access with basic system functionality',
      priority: 20,
      isSystem: true,
      isActive: true,
      permissions: getPermissionIds(userPermissionNames),
    },
  ];

  let upserted = 0;
  const roleMap = new Map();

  console.log(`   👥 Processing ${roles.length} roles (upsert)...`);

  for (const r of roles) {
    try {
      const doc = await Role.findOneAndUpdate(
        { name: r.name },
        {
          $set: {
            displayName: r.displayName,
            description: r.description,
            priority: r.priority,
            permissions: r.permissions,
            isSystem: true,
            isActive: true,
          }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      roleMap.set(r.name, doc._id);
      upserted++;
    } catch (error) {
      console.error(`   ❌ Error upserting role ${r.name}:`, error.message);
    }
  }

  console.log(`👥 Role hierarchy ready: ${upserted} upserted`);
  return roleMap;
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🗂️ DEFAULT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

const createDefaultCategories = async () => {
  console.log('🗂️  Creating default categories...');

  const buildDerived = async (parentDoc, slug) => {
    if (!parentDoc) return { path: [], fullSlug: slug, level: 0 };
    return {
      path: [...(parentDoc.path || []), parentDoc._id],
      fullSlug: `${parentDoc.fullSlug}/${slug}`,
      level: (parentDoc.level || 0) + 1,
    };
  };

  const upsertCategory = async ({ name, slug, description, order = 0, isActive = true }, parentDoc = null) => {
    const derived = await buildDerived(parentDoc, slug);
    const filter = { parent: parentDoc ? parentDoc._id : null, slug };

    const update = {
      $set: {
        name,
        slug,
        description: description || undefined,
        parent: parentDoc ? parentDoc._id : null,
        path: derived.path,
        fullSlug: derived.fullSlug,
        level: derived.level,
        order,
        isActive,
        isSystem: false,
      }
    };

    try {
      const doc = await Category.findOneAndUpdate(filter, update, {
        upsert: true, new: true, setDefaultsOnInsert: true
      });
      return { doc, created: doc.createdAt && doc.createdAt.getTime() === doc.updatedAt.getTime() };
    } catch (e) {
      const existing = await Category.findOne(filter);
      if (existing) {
        await Category.updateOne({ _id: existing._id }, update.$set);
        const doc = await Category.findById(existing._id);
        return { doc, created: false };
      }
      throw e;
    }
  };

  const tree = [
    {
      name: 'Electronics', slug: 'electronics', order: 1, children: [
        {
          name: 'Phones', slug: 'phones', order: 1, children: [
            { name: 'Smartphones', slug: 'smartphones', order: 1 },
            { name: 'Feature Phones', slug: 'feature-phones', order: 2 },
          ]
        },
        {
          name: 'Computers', slug: 'computers', order: 2, children: [
            { name: 'Laptops', slug: 'laptops', order: 1 },
            { name: 'Desktops', slug: 'desktops', order: 2 },
          ]
        },
        { name: 'Accessories', slug: 'accessories', order: 3 }
      ]
    },
    {
      name: 'Apparel', slug: 'apparel', order: 2, children: [
        {
          name: 'Men', slug: 'men', order: 1, children: [
            { name: 'Shirts', slug: 'shirts', order: 1 },
            { name: 'Pants', slug: 'pants', order: 2 },
          ]
        },
        {
          name: 'Women', slug: 'women', order: 2, children: [
            { name: 'Dresses', slug: 'dresses', order: 1 },
            { name: 'Shoes', slug: 'shoes', order: 2 },
          ]
        }
      ]
    }
  ];

  let created = 0;
  let updated = 0;

  const walk = async (nodes, parent = null) => {
    for (const n of nodes) {
      const { doc, created: c } = await upsertCategory(n, parent);
      if (c) created++; else updated++;
      if (n.children && n.children.length) {
        await walk(n.children, doc);
      }
    }
  };

  await walk(tree, null);

  console.log(`   ✅ Categories ready: ${created} created, ${updated} updated`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// 👤 USER CREATION
// ═══════════════════════════════════════════════════════════════════════════════

const createSuperAdmin = async (roleMap) => {
  console.log('👑 Creating super administrator...');

  const superAdminRoleId = roleMap.get(ROLES.SUPER_ADMIN);
  if (!superAdminRoleId) throw new Error('Super Admin role not found. Role creation may have failed.');

  const existing = await User.findOne({ email: ADMIN_EMAIL });

  if (!existing) {
    const superAdminData = {
      firstName: 'Super',
      lastName: 'Administrator',
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD, // hashed by pre-save
      roles: [superAdminRoleId],
      isActive: true,
      isEmailVerified: true,
      profile: { timezone: 'Europe/Istanbul', language: 'tr', avatar: null },
      metadata: { createdBy: null, updatedBy: null, ipAddress: '127.0.0.1', userAgent: 'System Seed Script' },
    };

    await User.create(superAdminData);
    console.log('   ✅ Super Administrator created successfully');
    console.log(`   📧 Email: ${ADMIN_EMAIL}`);
    console.log(`   🔑 Password: ${ADMIN_PASSWORD}`);
  } else {
    await User.findByIdAndUpdate(existing._id, {
      roles: [superAdminRoleId],
      isActive: true,
      isEmailVerified: true,
    });
    console.log('   🔄 Super Administrator updated successfully');
  }
};

const createTestUsers = async (roleMap) => {
  console.log('👥 Creating test users...');

  const testUsers = [
    // Administrative Users
    { firstName: 'Admin', lastName: 'Manager', email: 'admin@test.com', password: 'Admin123!', role: ROLES.ADMIN },
    { firstName: 'System', lastName: 'Administrator', email: 'sysadmin@test.com', password: 'SysAdmin123!', role: ROLES.ADMIN },

    // Moderator Users
    { firstName: 'Content', lastName: 'Moderator', email: 'moderator@test.com', password: 'Moderator123!', role: ROLES.MODERATOR },
    { firstName: 'Community', lastName: 'Manager', email: 'community@test.com', password: 'Community123!', role: ROLES.MODERATOR },

    // Standard Users
    { firstName: 'John', lastName: 'Smith', email: 'john.smith@test.com', password: 'User123!', role: ROLES.USER },
    { firstName: 'Jane', lastName: 'Doe', email: 'jane.doe@test.com', password: 'User123!', role: ROLES.USER },
    { firstName: 'Test', lastName: 'User', email: 'test@test.com', password: 'Test123!', role: ROLES.USER },

    // Special Purpose
    { firstName: 'Demo', lastName: 'Administrator', email: 'demo@admin.com', password: 'Demo123!', role: ROLES.ADMIN },
    { firstName: 'Guest', lastName: 'Moderator', email: 'guest@moderator.com', password: 'Guest123!', role: ROLES.MODERATOR },
  ];

  let createdCount = 0;
  let updatedCount = 0;

  console.log(`   👤 Processing ${testUsers.length} test users...`);

  for (const u of testUsers) {
    try {
      const existing = await User.findOne({ email: u.email });
      const roleId = roleMap.get(u.role);
      if (!roleId) {
        console.error(`   ❌ Role not found for user ${u.email}: ${u.role}`);
        continue;
      }

      if (!existing) {
        const newUser = {
          firstName: u.firstName,
          lastName: u.lastName,
          email: u.email,
          password: u.password, // hashed by pre-save
          roles: [roleId],
          isActive: true,
          isEmailVerified: true,
          profile: { timezone: 'Europe/Istanbul', language: 'tr' },
          metadata: { createdBy: null, updatedBy: null, ipAddress: '127.0.0.1', userAgent: 'System Seed Script' },
        };

        await User.create(newUser);
        console.log(`   ✅ Created: ${u.email} (${u.role})`);
        createdCount++;
      } else {
        await User.findByIdAndUpdate(existing._id, {
          roles: [roleId],
          isActive: true,
          isEmailVerified: true,
        });
        console.log(`   🔄 Updated: ${u.email} (${u.role})`);
        updatedCount++;
      }
    } catch (error) {
      console.error(`   ❌ Error creating user ${u.email}:`, error.message);
    }
  }

  console.log(`👥 Test users ready: ${createdCount} created, ${updatedCount} updated`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// 📊 SYSTEM VALIDATION & REPORTING
// ═══════════════════════════════════════════════════════════════════════════════

const validateSystemIntegrity = async () => {
  console.log('🔍 Validating system integrity...');

  const issues = [];

  try {
    // Permission integrity
    const permissions = await Permission.find({ isActive: true });
    const invalidPermissions = permissions.filter((p) => !p.name || !p.resource || !p.action || !p.category);
    if (invalidPermissions.length > 0) issues.push(`❌ ${invalidPermissions.length} permissions have missing required fields`);

    // Role integrity
    const roles = await Role.find({ isActive: true }).populate('permissions');
    for (const role of roles) {
      const invalidRefs = role.permissions.filter((p) => !p || !p.isActive);
      if (invalidRefs.length > 0) issues.push(`❌ Role '${role.name}' has ${invalidRefs.length} invalid permission references`);
    }

    // User integrity
    const users = await User.find({ isActive: true }).populate('roles');
    for (const user of users) {
      const invalidRoleRefs = user.roles.filter((r) => !r || !r.isActive);
      if (invalidRoleRefs.length > 0) issues.push(`❌ User '${user.email}' has ${invalidRoleRefs.length} invalid role references`);
    }

    if (issues.length === 0) {
      console.log('   ✅ System integrity validation passed');
    } else {
      console.log('   ⚠️ System integrity issues found:');
      issues.forEach((i) => console.log(`     ${i}`));
    }

    return issues.length === 0;
  } catch (error) {
    console.error('   ❌ Error during integrity validation:', error.message);
    return false;
  }
};

const generateSystemReport = async () => {
  try {
    const [permissionCount, roleCount, userCount, categoryCount, rootCount] = await Promise.all([
      Permission.countDocuments({ isActive: true }),
      Role.countDocuments({ isActive: true }),
      User.countDocuments({ isActive: true }),
      Category.countDocuments({}),
      Category.countDocuments({ parent: null }),
    ]);

    const allPermissions = await Permission.find({ isActive: true }).select('name displayName category').lean();
    const roleDetails = await Role.find({ isActive: true })
      .populate('permissions', 'name')
      .select('name displayName permissions priority')
      .sort({ priority: -1 })
      .lean();

    const usersByRole = await User.aggregate([
      { $match: { isActive: true } },
      { $unwind: '$roles' },
      { $lookup: { from: 'roles', localField: 'roles', foreignField: '_id', as: 'roleData' } },
      { $unwind: '$roleData' },
      { $group: { _id: '$roleData.name', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    console.log('\n🎉 ADMIN PANEL SYSTEM READY! 🎉\n');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('📊 SYSTEM OVERVIEW');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`   📋 Active Permissions: ${permissionCount}`);
    console.log(`   👥 Active Roles      : ${roleCount}`);
    console.log(`   👤 Active Users      : ${userCount}`);
    console.log(`   🗂️  Categories       : ${categoryCount} (roots: ${rootCount})\n`);

    console.log('🔐 AUTHENTICATION CREDENTIALS');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`   🌟 Super Admin    : ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
    console.log('   👔 Admin User     : admin@test.com / Admin123!');
    console.log('   🏢 System Admin   : sysadmin@test.com / SysAdmin123!');
    console.log('   🛡️  Moderator     : moderator@test.com / Moderator123!');
    console.log('   🤝 Community Mgr  : community@test.com / Community123!');
    console.log('   👤 John Smith     : john.smith@test.com / User123!');
    console.log('   👤 Jane Doe       : jane.doe@test.com / User123!');
    console.log('   🧪 Test User      : test@test.com / Test123!');
    console.log('   🎪 Demo Admin     : demo@admin.com / Demo123!');
    console.log('   👻 Guest Moderator: guest@moderator.com / Guest123!\n');

    console.log('👥 ROLE HIERARCHY & PERMISSIONS');
    console.log('═══════════════════════════════════════════════════════════════');
    roleDetails.forEach((role) => {
      console.log(`   ${role.displayName} (${role.name}): ${role.permissions.length} permissions`);
    });

    if (usersByRole.length > 0) {
      console.log('\n📈 USER DISTRIBUTION');
      console.log('═══════════════════════════════════════════════════════════════');
      usersByRole.forEach((stat) => console.log(`   ${stat._id}: ${stat.count} users`));
    }

    console.log('\n🚀 SYSTEM FEATURES');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('   ✅ Role-Based Access Control (RBAC)');
    console.log('   ✅ JWT Authentication with Refresh Tokens');
    console.log('   ✅ Comprehensive Audit Logging');
    console.log('   ✅ Rate Limiting & Security Middleware');
    console.log('   ✅ Multi-language Support (TR/EN/DE)');
    console.log('   ✅ Error Handling');
    console.log('   ✅ MongoDB with Optimized Indexes');
    console.log('   ✅ Input Validation & Sanitization');
    console.log('   ✅ Session Management & Security');
    console.log('   ✅ API Documentation');
    console.log('   ✅ Category Module (Hierarchy, move, status, ordering)');

    console.log('\n📋 PERMISSION CATEGORIES');
    console.log('═══════════════════════════════════════════════════════════════');
    const categories = Object.values(PERMISSION_CATEGORIES);
    categories.forEach((category) => {
      const categoryPermissions = allPermissions.filter((p) => p.category === category);
      console.log(`   📁 ${category}: ${categoryPermissions.length} permissions`);
    });

    console.log('\n🎯 NEXT STEPS');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('   1. 🌐 Start your application: npm start');
    console.log('   2. 🔑 Login with super admin credentials');
    console.log('   3. 🧪 Test different user roles and permissions');
    console.log('   4. 🗂️  Explore category tree endpoints');
    console.log('   5. 📊 Check audit logs for activity tracking');
    console.log('   6. 🛡️  Configure additional security settings');

    console.log('\n✅ ADMIN PANEL IS READY! 🎊');
    console.log('═══════════════════════════════════════════════════════════════\n');
  } catch (error) {
    console.error('❌ Error generating system report:', error.message);
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🚀 MAIN SEEDING ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

const safeExit = async (code) => {
  try { await mongoose.disconnect(); } catch (_) { }
  process.exit(code);
};

const seedData = async (options = {}) => {
  const startTime = Date.now();

  try {
    console.log('🚀 STARTING ADMIN PANEL SEED PROCESS...\n');
    console.log('═══════════════════════════════════════════════════════════════');

    // Step 1: Database Connection
    await connectDB();

    // Step 2: Optional Data Cleanup
    if (options.clearData !== false) {
      await clearExistingData({
        preserveSystemData: options.preserveSystemData !== false,
        preserveSuperAdmin: options.preserveSuperAdmin !== false,
      });
    }

    // Step 3: Create Permission System
    console.log('\n🔑 PHASE 1: PERMISSION SYSTEM');
    console.log('───────────────────────────────────────────────────────────────');
    const permissionMap = await createPermissions();

    // Step 4: Create Role Hierarchy
    console.log('\n👥 PHASE 2: ROLE HIERARCHY');
    console.log('───────────────────────────────────────────────────────────────');
    const roleMap = await createRoles(permissionMap);

    // Step 5: Create Super Administrator
    console.log('\n👑 PHASE 3: SUPER ADMINISTRATOR');
    console.log('───────────────────────────────────────────────────────────────');
    await createSuperAdmin(roleMap);

    // Step 6: Create Test Users
    console.log('\n👤 PHASE 4: TEST USERS');
    console.log('───────────────────────────────────────────────────────────────');
    await createTestUsers(roleMap);

    // Step 7: Default Categories
    console.log('\n🗂️  PHASE 5: DEFAULT CATEGORIES');
    console.log('───────────────────────────────────────────────────────────────');
    await createDefaultCategories();

    // Step 8: System Validation
    console.log('\n🔍 PHASE 6: VALIDATION');
    console.log('───────────────────────────────────────────────────────────────');
    const isValid = await validateSystemIntegrity();
    if (!isValid) {
      console.warn('⚠️ System validation found issues, but seeding completed');
    }

    // Step 9: Generate Report
    console.log('\n📊 PHASE 7: REPORTING');
    console.log('───────────────────────────────────────────────────────────────');
    await generateSystemReport();

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`🏁 SEEDING COMPLETED SUCCESSFULLY IN ${duration}s! 🏁`);

    await safeExit(0);
  } catch (error) {
    console.error('\n💥 CRITICAL SEEDING ERROR:', error);
    console.error('Stack trace:', error.stack);

    console.log('\n🔧 TROUBLESHOOTING TIPS:');
    console.log('   1. Check MongoDB connection');
    console.log('   2. Verify environment variables');
    console.log('   3. Ensure proper permissions');
    console.log('   4. Check for existing data conflicts');

    await safeExit(1);
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🎯 EXECUTION & EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {
    clearData: !args.includes('--no-clear'),
    preserveSystemData: !args.includes('--force-clear'),
    preserveSuperAdmin: !args.includes('--reset-admin'),
  };

  console.log('🎛️  Seeding Options:', options);
  seedData(options);
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
