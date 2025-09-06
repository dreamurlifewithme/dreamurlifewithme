const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

const multer = require('multer'); // Add this line

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files
app.set('view engine', 'ejs'); // Set EJS as the templating engine
app.set('views', path.join(__dirname, 'views')); // Set views directory

// Session middleware
app.use(session({
    secret: 'your_secret_key', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, 'public', 'uploads', 'profile_pics');
        // Ensure the directory exists
        require('fs').mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, req.session.userId + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Database setup
const dbPath = path.join(__dirname, 'database', 'dreamurlife.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            dob TEXT NOT NULL,
            city TEXT NOT NULL,
            contact TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_winner INTEGER DEFAULT 0,
            winner_position TEXT DEFAULT NULL,
            status TEXT DEFAULT 'Active',
            profile_pic TEXT DEFAULT NULL  -- Added profile_pic column
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            }
        });
    }
});

// Prize Definitions
const prizes = [
    { position: '1st', name: 'Bike', image: '/images/prizes/1_Prize_Bike.jpeg' },
    { position: '2nd', name: 'Smart Mobile', image: '/images/prizes/2_Prize_Smart_Mobile.jpeg' },
    { position: '3rd', name: 'Gold Coin', image: '/images/prizes/3_Prize_Gold_Coin.jpeg' },
    { position: '4th-10th', name: 'Gift Card', image: '/images/prizes/4_to_10_Prize_Gift_Card.jpeg' }
];

// Helper function to generate a random alphanumeric string of a given length
function generateRandomAlphanumericString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Routes
app.get('/', (req, res) => {
    res.render('index', { title: 'Welcome to DREAMURLIFEWITHME', prizes: prizes });
});

// User Registration GET route
app.get('/register', (req, res) => {
    res.render('register', { message: null });
});

// User Registration POST route
app.post('/register', async (req, res) => {
    const { name, dob, city, contact, email, userId, password, confirmPassword } = req.body; // Added userId

    // Basic server-side validation
    if (!name || !dob || !city || !contact || !email || !userId || !password || !confirmPassword) { // Added userId
        return res.render('register', { message: 'All fields are required.' });
    }

    // Validate email format
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.render('register', { message: 'Invalid email format.' });
    }

    // Validate contact number (10 digits)
    if (!/^\d{10}$/.test(contact)) {
        return res.render('register', { message: 'Contact number must be 10 digits.' });
    }

    // Validate User ID format (e.g., alphanumeric, 6-15 characters)
    if (!/^[a-zA-Z0-9]{6,15}$/.test(userId)) {
        return res.render('register', { message: 'User ID must be 6-15 alphanumeric characters.' });
    }

    // Validate password length
    if (password.length < 6) {
        return res.render('register', { message: 'Password must be at least 6 characters long.' });
    }

    // Validate password match
    if (password !== confirmPassword) {
        return res.render('register', { message: 'Passwords do not match.' });
    }

    try {
        // Check if email already exists
        const existingUserByEmail = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUserByEmail) {
            return res.render('register', { message: 'Email already registered.' });
        }

        // Check if User ID already exists
        const existingUserById = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUserById) {
            return res.render('register', { message: 'User ID already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash the user-provided password

        db.run('INSERT INTO users (id, name, dob, city, contact, email, password) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, name, dob, city, contact, email, hashedPassword],
            function (err) {
                if (err) {
                    console.error('Error inserting user:', err.message);
                    return res.render('register', { message: 'Error registering user.' });
                }
                // Render a success page or message with UserID (password is user-provided)
                res.render('registration_success', { userId: userId, rawPassword: password }); // Pass user-provided password
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { message: 'An unexpected error occurred.' });
    }
});

// Upload Photo GET route
app.get('/upload-photo', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('upload_photo', { message: null });
});

// Upload Photo POST route
app.post('/upload-photo', upload.single('profilePic'), async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    if (!req.file) {
        return res.render('upload_photo', { message: 'Please select an image to upload.' });
    }

    const profilePicPath = '/uploads/profile_pics/' + req.file.filename;

    try {
        db.run('UPDATE users SET profile_pic = ? WHERE id = ?', [profilePicPath, req.session.userId], (err) => {
            if (err) {
                console.error('Error updating profile picture:', err.message);
                return res.render('upload_photo', { message: 'Error uploading photo.' });
            }
            // Update session user data
            req.session.user.profile_pic = profilePicPath;
            res.render('upload_photo', { message: 'Photo uploaded successfully!', success: true });
        });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.render('upload_photo', { message: 'An unexpected error occurred.' });
    }
});

// User Login GET route
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

// User Login POST route
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.render('login', { message: 'Please enter both User ID and Password.' });
    }

    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!user) {
            return res.render('login', { message: 'Invalid User ID or Password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            req.session.userId = user.id; // Store user ID in session
            req.session.user = user; // Store user object in session
            res.redirect('/dashboard'); // Redirect to user dashboard
        } else {
            res.render('login', { message: 'Invalid User ID or Password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { message: 'An unexpected error occurred.' });
    }
});

// User Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    // Fetch total users and active users
    db.get('SELECT COUNT(*) AS totalUsers FROM users', (err, totalUsersRow) => {
        if (err) {
            console.error('Error fetching total users:', err.message);
            return res.render('dashboard', { user: req.session.user, message: 'Error loading dashboard.', prizes: prizes, totalUsers: 0, activeUsers: 0 });
        }
        db.get('SELECT COUNT(*) AS activeUsers FROM users WHERE status = \'Active\'', (err, activeUsersRow) => {
            if (err) {
                console.error('Error fetching active users:', err.message);
                return res.render('dashboard', { user: req.session.user, message: 'Error loading dashboard.', prizes: prizes, totalUsers: totalUsersRow.totalUsers, activeUsers: 0 });
            }
            res.render('dashboard', {
                user: req.session.user,
                message: null,
                prizes: prizes,
                totalUsers: totalUsersRow.totalUsers,
                activeUsers: activeUsersRow.activeUsers
            });
        });
    });
});

// Edit Profile GET route
app.get('/edit-profile', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('edit_profile', { user: req.session.user, message: null });
});

// Edit Profile POST route
app.post('/edit-profile', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const { name, dob, city, contact, email, newPassword, confirmNewPassword } = req.body;
    const currentUserId = req.session.userId;

    // Basic validation
    if (!name || !dob || !city || !contact || !email) {
        return res.render('edit_profile', { user: req.session.user, message: 'All fields except new password are required.' });
    }

    // Validate email format
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.render('edit_profile', { user: req.session.user, message: 'Invalid email format.' });
    }

    // Validate contact number (10 digits)
    if (!/^\d{10}$/.test(contact)) {
        return res.render('edit_profile', { user: req.session.user, message: 'Contact number must be 10 digits.' });
    }

    let hashedPassword = req.session.user.password; // Default to current hashed password

    if (newPassword) {
        if (newPassword.length < 6) {
            return res.render('edit_profile', { user: req.session.user, message: 'New password must be at least 6 characters long.' });
        }
        if (newPassword !== confirmNewPassword) {
            return res.render('edit_profile', { user: req.session.user, message: 'New passwords do not match.' });
        }
        hashedPassword = await bcrypt.hash(newPassword, 10);
    }

    try {
        // Check if email is already taken by another user
        const existingUserByEmail = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ? AND id != ?', [email, currentUserId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUserByEmail) {
            return res.render('edit_profile', { user: req.session.user, message: 'Email already taken by another user.' });
        }

        db.run('UPDATE users SET name = ?, dob = ?, city = ?, contact = ?, email = ?, password = ? WHERE id = ?',
            [name, dob, city, contact, email, hashedPassword, currentUserId],
            function (err) {
                if (err) {
                    console.error('Error updating user profile:', err.message);
                    return res.render('edit_profile', { user: req.session.user, message: 'Error updating profile.' });
                }
                // Update session user data
                req.session.user = { ...req.session.user, name, dob, city, contact, email, password: hashedPassword };
                res.render('edit_profile', { user: req.session.user, message: 'Profile updated successfully!' });
            }
        );
    } catch (error) {
        console.error('Edit profile error:', error);
        res.render('edit_profile', { user: req.session.user, message: 'An unexpected error occurred.' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.redirect('/dashboard'); // Or show an error page
        }
        res.redirect('/login');
    });
});

// Forgot Password GET route
app.get('/forgot-password', (req, res) => {
    res.render('forgot_password', { message: null });
});

// Forgot Password POST route
app.post('/forgot-password', async (req, res) => {
    const { contact } = req.body;

    if (!contact) {
        return res.render('forgot_password', { message: 'Please enter your contact number.' });
    }

    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE contact = ?', [contact], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!user) {
            return res.render('forgot_password', { message: 'No user found with that contact number.' });
        }

        // Generate a new temporary password
        const newTempPassword = generateRandomAlphanumericString(8); // Reusing the function
        const hashedNewPassword = await bcrypt.hash(newTempPassword, 10);

        // Update user's password in the database
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, user.id], (err) => {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.render('forgot_password', { message: 'Error resetting password.' });
            }
            res.render('forgot_password_success', { newPassword: newTempPassword });
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.render('forgot_password', { message: 'An unexpected error occurred.' });
    }
});

// Admin Login GET route
app.get('/admin/login', (req, res) => {
    res.render('admin_login', { message: null });
});

// Admin Login POST route
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    // Hardcoded admin credentials
    const ADMIN_USERNAME = 'DREAMURLIFEWITHME';
    const ADMIN_PASSWORD = 'Raju@4832';

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true; // Set admin session
        res.redirect('/admin/dashboard');
    } else {
        res.render('admin_login', { message: 'Invalid Admin Username or Password.' });
    }
});

// Admin Dashboard
app.get('/admin/dashboard', (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login'); // Redirect to admin login if not authenticated
    }

    // Fetch total users and active users
    db.get('SELECT COUNT(*) AS totalUsers FROM users', (err, totalUsersRow) => {
        if (err) {
            console.error('Error fetching total users for admin dashboard:', err.message);
            return res.render('admin_dashboard', { users: [], message: 'Error loading users.', prizes: prizes, winners: [], totalUsers: 0, activeUsers: 0 });
        }
        db.get('SELECT COUNT(*) AS activeUsers FROM users WHERE status = \'Active\'', (err, activeUsersRow) => {
            if (err) {
                console.error('Error fetching active users for admin dashboard:', err.message);
                return res.render('admin_dashboard', { users: [], message: 'Error loading users.', prizes: prizes, winners: [], totalUsers: totalUsersRow.totalUsers, activeUsers: 0 });
            }
            // Fetch all users from the database
            db.all('SELECT * FROM users', [], (err, users) => {
                if (err) {
                    console.error('Error fetching users for admin dashboard:', err.message);
                    return res.render('admin_dashboard', { users: [], message: 'Error loading users.', prizes: prizes, winners: [], totalUsers: totalUsersRow.totalUsers, activeUsers: activeUsersRow.activeUsers });
                }
                // For now, winners array is empty. Will be populated after draw logic.
                res.render('admin_dashboard', {
                    users: users,
                    message: null,
                    prizes: prizes,
                    winners: [],
                    totalUsers: totalUsersRow.totalUsers,
                    activeUsers: activeUsersRow.activeUsers
                });
            });
        });
    });
});

// Admin Toggle User Status
app.post('/admin/toggle-status/:id', (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    const userId = req.params.id;
    db.get('SELECT status FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error fetching user status:', err.message);
            return res.redirect('/admin/dashboard');
        }
        const newStatus = row.status === 'Active' ? 'Deactivated' : 'Active';
        db.run('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (err) => {
            if (err) {
                console.error('Error updating user status:', err.message);
            }
            res.redirect('/admin/dashboard');
        });
    });
});

// Admin Delete User
app.post('/admin/delete-user/:id', (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    const userId = req.params.id;
    db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) {
            console.error('Error deleting user:', err.message);
        }
        res.redirect('/admin/dashboard');
    });
});

// Admin Logout route
app.post('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying admin session:', err);
            return res.redirect('/admin/dashboard');
        }
        res.redirect('/admin/login');
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
