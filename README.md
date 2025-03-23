Express Blog App

A secure and dynamic Blog Application built with Express.js, EJS, and SQLite, offering full CRUD functionality. This project emphasizes secure authentication, data handling, and user experience, making it an excellent showcase of backend and database skills.

🛠️ Key Features

User Authentication:

Secure password storage with bcrypt hashing.

User sessions managed via JWT tokens and HTTP cookies.

CRUD Operations:

Users can Create, Read, Update, and Delete blog posts.

User Validation:

Checks for duplicate usernames during account creation.

Sanitizes user input using sanitize-html to prevent XSS attacks.

Dynamic Content:

Displays posts in reverse chronological order (newest first).

Personalized dashboard with contextual messages (e.g., "No posts yet").

Secure Routes:

Restricts post editing and deletion to the post owner.

Protects routes using middleware to ensure only logged-in users can access specific pages.

🧰 Technologies Used

Backend: Express.js

Frontend: EJS (Embedded JavaScript)

Database: SQLite

Security: bcrypt (password hashing), JWT (authentication), sanitize-html (input sanitization)
