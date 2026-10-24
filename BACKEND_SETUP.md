# SwiftCart Node.js and MySQL setup

The Express API in `backend.js` serves the project files and provides the operations dashboard API. The storefront's existing `server.js` file is an HTML page; keep it unchanged.

## Requirements

- Node.js 18 or later
- MySQL 8 or XAMPP MySQL

## Setup

1. Create the database and tables by running `database.sql` in MySQL Workbench, phpMyAdmin, or the MySQL command-line client.
2. Install Node dependencies:

   ```powershell
   npm install
   ```

3. Copy `.env.example` to `.env` and set `DB_USER` and `DB_PASSWORD` to your MySQL credentials.
4. Start the app from the project directory:

   ```powershell
   npm start
   ```

5. Open `http://localhost:5000/admin_analytics.html`. The dashboard API is served from the same origin.

The admin API reads hub data, today's orders and sales, low-stock products, and active orders from MySQL. Checkout locks inventory rows, rejects quantities above available stock, and deducts sold units when the order transaction commits. Reorder buttons create pending purchase-order records; they do not mark inventory as received. Picker assignments and delivery SLA timing are not part of the current database schema.

Customers create an account with their name, phone number, delivery address, and a password of at least 8 characters. Later, they sign in with their phone number and password. Passwords are stored as scrypt hashes, and authenticated sessions are stored in the `customer_sessions` table. Run the updated `database.sql` to add password support and create the session table. The storefront uses the authenticated profile at checkout, and the profile's order history is loaded from MySQL and refreshed periodically.

Customers can cancel their own orders while the status is `PACKED` (before dispatch). Cancellation changes the order status to `CANCELLED` and returns its item quantities to product stock in one database transaction. Dispatched or completed orders cannot be cancelled through the customer page.

If you already had a customer session from the previous OTP version, stay signed in and set a password under Profile Settings before signing out. Existing accounts without a password cannot use password login until they do this. Delivery handover OTPs are separate and remain part of order delivery.

`GET /api/health` checks the database connection and required tables/columns; run `database.sql` if it reports an incomplete schema. Admin API routes are intended for local project use; add authentication and authorization before exposing them to a public network.
