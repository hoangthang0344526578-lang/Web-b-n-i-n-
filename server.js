const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'nexphone-super-secret-key-2026';

app.use(cors());
app.use(express.json());

// Paths to JSON data files
const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Helpers for Reading / Writing JSON files
function readData(filePath, fallback = []) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(fallback, null, 2), 'utf-8');
      return fallback;
    }
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error(`Error reading ${filePath}:`, err);
    return fallback;
  }
}

function writeData(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error(`Error writing to ${filePath}:`, err);
    return false;
  }
}

// Password hashing and Token helpers using Node crypto
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + SECRET_KEY).digest('hex');
}

function generateToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
  };
  const str = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(str).digest('hex');
  return `${str}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [str, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(str).digest('hex');
  if (signature !== expectedSig) return null;

  try {
    const payload = JSON.parse(Buffer.from(str, 'base64').toString('utf-8'));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Middleware: Authenticate User
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }
  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);
  if (payload) {
    const users = readData(USERS_FILE);
    const user = users.find(u => u.id === payload.id);
    req.user = user || payload;
  } else {
    req.user = null;
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Vui lòng đăng nhập để tiếp tục' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Vui lòng đăng nhập' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Quyền truy cập bị từ chối. Chỉ dành cho Quản trị viên (Admin)' });
  }
  next();
}

app.use(authenticate);

// ---------------------------------------------------------------------
// HEALTH CHECK
// ---------------------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    storeName: 'NexPhone Mobile Store API',
    version: '1.0.0',
    time: new Date().toISOString()
  });
});

// ---------------------------------------------------------------------
// AUTH ROUTES (Đăng ký, Đăng nhập, Demo Switch, Info)
// ---------------------------------------------------------------------
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, phone, address } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Vui lòng nhập đầy đủ họ tên, email và mật khẩu' });
  }

  const users = readData(USERS_FILE);
  const normalizedEmail = email.trim().toLowerCase();
  if (users.some(u => u.email.toLowerCase() === normalizedEmail)) {
    return res.status(400).json({ error: 'Email này đã được đăng ký tài khoản' });
  }

  const newUser = {
    id: `user-${Date.now()}`,
    name: name.trim(),
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    role: 'user', // Default role is user
    phone: phone ? phone.trim() : '',
    address: address ? address.trim() : '',
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeData(USERS_FILE, users);

  const token = generateToken(newUser);
  const { passwordHash, ...userWithoutPassword } = newUser;
  res.status(201).json({
    message: 'Đăng ký tài khoản thành công',
    token,
    user: userWithoutPassword
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Vui lòng nhập email và mật khẩu' });
  }

  const users = readData(USERS_FILE);
  const normalizedEmail = email.trim().toLowerCase();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);

  if (!user) {
    return res.status(401).json({ error: 'Email hoặc mật khẩu không chính xác' });
  }

  // Support demo passwords: "password", "admin123", "user123", or matching hash
  const demoPasswords = ['password', 'admin123', 'user123', '123456'];
  const isValidDemo = demoPasswords.includes(password);
  const isValidHash = user.passwordHash === hashPassword(password) || user.passwordHash === crypto.createHash('sha256').update(password).digest('hex');

  if (!isValidHash && !isValidDemo) {
    return res.status(401).json({ error: 'Email hoặc mật khẩu không chính xác' });
  }

  const token = generateToken(user);
  const { passwordHash, ...userWithoutPassword } = user;
  res.json({
    message: 'Đăng nhập thành công',
    token,
    user: userWithoutPassword
  });
});

// Quick 1-click login for demo purposes (Admin or Customer)
app.post('/api/auth/demo-login', (req, res) => {
  const { role } = req.body;
  const users = readData(USERS_FILE);
  let targetUser = users.find(u => u.role === (role === 'admin' ? 'admin' : 'user'));

  if (!targetUser) {
    // If none found, create fallback
    if (role === 'admin') {
      targetUser = {
        id: 'user-admin',
        name: 'Quản Trị Viên (Admin)',
        email: 'admin@phonestore.vn',
        passwordHash: hashPassword('admin123'),
        role: 'admin',
        phone: '0988888888',
        address: 'Hà Nội',
        createdAt: new Date().toISOString()
      };
    } else {
      targetUser = {
        id: 'user-demo-customer',
        name: 'Nguyễn Văn An (Khách hàng)',
        email: 'khachhang@gmail.com',
        passwordHash: hashPassword('user123'),
        role: 'user',
        phone: '0912345678',
        address: 'Số 45 Giải Phóng, Hà Nội',
        createdAt: new Date().toISOString()
      };
    }
    users.push(targetUser);
    writeData(USERS_FILE, users);
  }

  const token = generateToken(targetUser);
  const { passwordHash, ...userWithoutPassword } = targetUser;
  res.json({
    message: `Đã chuyển sang tài khoản ${role === 'admin' ? 'Quản Trị Viên' : 'Khách hàng'}`,
    token,
    user: userWithoutPassword
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const { passwordHash, ...safeUser } = req.user;
  res.json({ user: safeUser });
});

// ---------------------------------------------------------------------
// PRODUCT ROUTES
// ---------------------------------------------------------------------
app.get('/api/products', (req, res) => {
  let products = readData(PRODUCTS_FILE);
  const { brand, search, minPrice, maxPrice, sort, featured } = req.query;

  // Filter by Brand
  if (brand && brand !== 'All') {
    products = products.filter(p => p.brand.toLowerCase() === brand.toLowerCase());
  }

  // Filter by Search Query
  if (search && search.trim() !== '') {
    const q = search.trim().toLowerCase();
    products = products.filter(p => {
      const nameMatch = p.name.toLowerCase().includes(q);
      const brandMatch = p.brand.toLowerCase().includes(q);
      const chipMatch = p.specs && p.specs.chip && p.specs.chip.toLowerCase().includes(q);
      return nameMatch || brandMatch || chipMatch;
    });
  }

  // Filter by Price range
  if (minPrice) {
    products = products.filter(p => p.price >= Number(minPrice));
  }
  if (maxPrice) {
    products = products.filter(p => p.price <= Number(maxPrice));
  }

  // Filter Featured
  if (featured === 'true') {
    products = products.filter(p => p.isFeatured);
  }

  // Sort
  if (sort === 'price_asc') {
    products.sort((a, b) => a.price - b.price);
  } else if (sort === 'price_desc') {
    products.sort((a, b) => b.price - a.price);
  } else if (sort === 'rating') {
    products.sort((a, b) => (b.rating || 0) - (a.rating || 0));
  } else if (sort === 'discount') {
    products.sort((a, b) => (b.discountPercent || 0) - (a.discountPercent || 0));
  }

  res.json(products);
});

app.get('/api/products/:id', (req, res) => {
  const products = readData(PRODUCTS_FILE);
  const product = products.find(p => p.id === req.params.id);
  if (!product) {
    return res.status(404).json({ error: 'Không tìm thấy sản phẩm' });
  }
  res.json(product);
});

// ADMIN: Create Product
app.post('/api/products', requireAdmin, (req, res) => {
  const {
    name, brand, price, originalPrice, image, stock,
    storage, storageOptions, colors, specs, description, badge, isFeatured
  } = req.body;

  if (!name || !brand || !price) {
    return res.status(400).json({ error: 'Tên, thương hiệu và giá bán là bắt buộc' });
  }

  const products = readData(PRODUCTS_FILE);
  const newProduct = {
    id: `prod-${Date.now()}`,
    name: name.trim(),
    brand: brand.trim(),
    price: Number(price),
    originalPrice: originalPrice ? Number(originalPrice) : Number(price),
    discountPercent: originalPrice && originalPrice > price
      ? Math.round(((originalPrice - price) / originalPrice) * 100)
      : 0,
    image: image || 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=800&auto=format&fit=crop&q=80',
    stock: stock !== undefined ? Number(stock) : 20,
    rating: 5.0,
    reviewsCount: 1,
    storage: storage || '128GB',
    storageOptions: storageOptions && storageOptions.length > 0 ? storageOptions : ['128GB', '256GB'],
    colors: colors && colors.length > 0 ? colors : [{ name: 'Mặc định', hex: '#333333', image: image }],
    specs: specs || {
      screen: '6.7 inch AMOLED 120Hz',
      chip: 'Snapdragon / Apple Bionic',
      ram: '8 GB',
      rom: '256 GB',
      battery: '5000 mAh',
      camera: '50 MP AI Camera',
      os: 'Android / iOS'
    },
    description: description || 'Điện thoại thông minh chính hãng, bảo hành 12 tháng.',
    badge: badge || 'Mới',
    isFeatured: !!isFeatured
  };

  products.unshift(newProduct);
  writeData(PRODUCTS_FILE, products);
  res.status(201).json({ message: 'Thêm sản phẩm thành công', product: newProduct });
});

// ADMIN: Update Product
app.put('/api/products/:id', requireAdmin, (req, res) => {
  const products = readData(PRODUCTS_FILE);
  const index = products.findIndex(p => p.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: 'Không tìm thấy sản phẩm' });
  }

  const updated = { ...products[index], ...req.body };
  if (req.body.price !== undefined) updated.price = Number(req.body.price);
  if (req.body.originalPrice !== undefined) updated.originalPrice = Number(req.body.originalPrice);
  if (req.body.stock !== undefined) updated.stock = Number(req.body.stock);

  if (updated.originalPrice && updated.originalPrice > updated.price) {
    updated.discountPercent = Math.round(((updated.originalPrice - updated.price) / updated.originalPrice) * 100);
  } else {
    updated.discountPercent = 0;
  }

  products[index] = updated;
  writeData(PRODUCTS_FILE, products);
  res.json({ message: 'Cập nhật sản phẩm thành công', product: updated });
});

// ADMIN: Delete Product
app.delete('/api/products/:id', requireAdmin, (req, res) => {
  let products = readData(PRODUCTS_FILE);
  const initialLength = products.length;
  products = products.filter(p => p.id !== req.params.id);

  if (products.length === initialLength) {
    return res.status(404).json({ error: 'Không tìm thấy sản phẩm cần xóa' });
  }

  writeData(PRODUCTS_FILE, products);
  res.json({ message: 'Đã xóa sản phẩm thành công' });
});

// ---------------------------------------------------------------------
// ORDERS ROUTES (Giỏ hàng & Đơn hàng)
// ---------------------------------------------------------------------
app.post('/api/orders', (req, res) => {
  const { customer, items, paymentMethod, discount, shippingFee, note } = req.body;

  if (!items || items.length === 0) {
    return res.status(400).json({ error: 'Giỏ hàng trống, không thể tạo đơn' });
  }
  if (!customer || !customer.name || !customer.phone || !customer.address) {
    return res.status(400).json({ error: 'Vui lòng điền họ tên, số điện thoại và địa chỉ nhận hàng' });
  }

  const products = readData(PRODUCTS_FILE);
  let subtotal = 0;

  // Deduct stock and calculate subtotal
  items.forEach(item => {
    subtotal += (item.price * item.quantity);
    const prod = products.find(p => p.id === item.id);
    if (prod && prod.stock >= item.quantity) {
      prod.stock -= item.quantity;
    }
  });
  writeData(PRODUCTS_FILE, products);

  const appliedDiscount = discount || 0;
  const appliedShipping = shippingFee !== undefined ? shippingFee : (subtotal > 15000000 ? 0 : 30000);
  const total = Math.max(0, subtotal - appliedDiscount + appliedShipping);

  const orders = readData(ORDERS_FILE);
  const orderId = `ORD-2026-${Math.floor(1000 + Math.random() * 9000)}`;

  const newOrder = {
    id: orderId,
    userId: req.user ? req.user.id : 'guest',
    customer: {
      name: customer.name.trim(),
      email: customer.email ? customer.email.trim() : (req.user ? req.user.email : ''),
      phone: customer.phone.trim(),
      address: customer.address.trim(),
      note: note || customer.note || ''
    },
    items,
    subtotal,
    discount: appliedDiscount,
    shippingFee: appliedShipping,
    total,
    paymentMethod: paymentMethod || 'COD', // COD, VietQR, MoMo, Bank
    paymentStatus: (paymentMethod === 'VietQR' || paymentMethod === 'MoMo') ? 'paid' : 'pending',
    status: 'pending', // pending, processing, shipping, delivered, cancelled
    createdAt: new Date().toISOString()
  };

  orders.unshift(newOrder);
  writeData(ORDERS_FILE, orders);

  res.status(201).json({
    message: 'Đặt hàng thành công!',
    order: newOrder
  });
});

app.get('/api/orders', requireAuth, (req, res) => {
  const orders = readData(ORDERS_FILE);
  // If admin: return all orders. If user: return only orders belonging to them
  if (req.user.role === 'admin') {
    return res.json(orders);
  }
  const userOrders = orders.filter(o => o.userId === req.user.id || (o.customer && o.customer.email === req.user.email));
  res.json(userOrders);
});

app.get('/api/orders/:id', requireAuth, (req, res) => {
  const orders = readData(ORDERS_FILE);
  const order = orders.find(o => o.id === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Không tìm thấy đơn hàng' });
  }

  // Check permission
  if (req.user.role !== 'admin' && order.userId !== req.user.id && order.customer.email !== req.user.email) {
    return res.status(403).json({ error: 'Bạn không có quyền xem đơn hàng này' });
  }

  res.json(order);
});

// ADMIN: Update Order Status
app.put('/api/orders/:id/status', requireAdmin, (req, res) => {
  const { status, paymentStatus } = req.body;
  const validStatuses = ['pending', 'processing', 'shipping', 'delivered', 'cancelled'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Trạng thái đơn hàng không hợp lệ' });
  }

  const orders = readData(ORDERS_FILE);
  const index = orders.findIndex(o => o.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Không tìm thấy đơn hàng' });
  }

  if (status) orders[index].status = status;
  if (paymentStatus) orders[index].paymentStatus = paymentStatus;
  orders[index].updatedAt = new Date().toISOString();

  writeData(ORDERS_FILE, orders);
  res.json({ message: 'Cập nhật trạng thái đơn hàng thành công', order: orders[index] });
});

// ---------------------------------------------------------------------
// ADMIN DASHBOARD STATS
// ---------------------------------------------------------------------
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const products = readData(PRODUCTS_FILE);
  const orders = readData(ORDERS_FILE);
  const users = readData(USERS_FILE);

  const totalRevenue = orders
    .filter(o => o.status !== 'cancelled')
    .reduce((sum, o) => sum + (o.total || 0), 0);

  const statusCounts = {
    pending: orders.filter(o => o.status === 'pending').length,
    processing: orders.filter(o => o.status === 'processing').length,
    shipping: orders.filter(o => o.status === 'shipping').length,
    delivered: orders.filter(o => o.status === 'delivered').length,
    cancelled: orders.filter(o => o.status === 'cancelled').length
  };

  // Brand sales
  const brandSales = {};
  orders.forEach(order => {
    if (order.status !== 'cancelled') {
      order.items.forEach(item => {
        // Find brand from products or item
        const prod = products.find(p => p.id === item.id);
        const brand = (prod && prod.brand) || 'Khác';
        brandSales[brand] = (brandSales[brand] || 0) + (item.price * item.quantity);
      });
    }
  });

  // Low stock products (< 10)
  const lowStock = products.filter(p => p.stock < 10);

  res.json({
    totalRevenue,
    totalOrders: orders.length,
    totalProducts: products.length,
    totalUsers: users.length,
    statusCounts,
    brandSales,
    lowStockCount: lowStock.length,
    recentOrders: orders.slice(0, 5)
  });
});

// ---------------------------------------------------------------------
// ADMIN USER MANAGEMENT
// ---------------------------------------------------------------------
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = readData(USERS_FILE);
  const safeUsers = users.map(u => {
    const { passwordHash, ...rest } = u;
    return rest;
  });
  res.json(safeUsers);
});

app.put('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body;
  if (!['admin', 'user'].includes(role)) {
    return res.status(400).json({ error: 'Vai trò chỉ có thể là admin hoặc user' });
  }

  const users = readData(USERS_FILE);
  const index = users.findIndex(u => u.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Không tìm thấy người dùng' });
  }

  // Prevent demoting the primary admin account if it's the last admin
  const admins = users.filter(u => u.role === 'admin');
  if (users[index].role === 'admin' && role !== 'admin' && admins.length <= 1) {
    return res.status(400).json({ error: 'Không thể hạ quyền Admin cuối cùng trong hệ thống' });
  }

  users[index].role = role;
  writeData(USERS_FILE, users);

  const { passwordHash, ...safeUser } = users[index];
  res.json({ message: 'Cập nhật phân quyền thành công', user: safeUser });
});

// Start Server
app.listen(PORT, () => {
  console.log(`NexPhone Backend API Server is running on port: ${PORT}`);
});