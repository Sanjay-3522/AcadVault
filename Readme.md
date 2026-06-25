# AcadVault 📚
**Unlock Your True Academic Potential**

![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

AcadVault is a comprehensive, client-side academic planner and productivity dashboard. Built entirely with vanilla front-end web technologies, this project serves as a robust case study in utilizing raw HTML, CSS, and JavaScript to create a fully functional, stateful Single Page Application (SPA) without relying on external libraries, frameworks, or backend databases.

## 🚀 Overview
AcadVault empowers students to manage their study schedules, track their progress, and maintain deep focus. By utilizing the browser's local storage and native APIs, it delivers a lightning-fast, private, and offline-capable experience. Every user's data is completely isolated and secured locally using advanced cryptographic hashing.

## ✨ Key Features
* **Secure Local Authentication:** Features a robust local login system utilizing the Web Crypto API for SHA-256 password hashing. Includes brute-force protection (lockout after 5 failed attempts) and session expiries.
* **Smart Session Planner:** Schedule study sessions with specific subjects, topics, dates, times, and priority levels. Includes a conflict-resolution engine for past-due scheduling.
* **Dynamic Dashboard & Progress Tracking:** Visualizes study habits with weekly charts, completion rates, and subject-specific progress bars.
* **Streak System:** Gamifies studying by tracking daily streaks (minimum 45 minutes/day requirement) to keep motivation high.
* **Integrated Focus Timer:** A built-in Pomodoro-style timer (Focus, Short Break, Long Break) that automatically logs studied minutes directly to today's goals.
* **Interactive Calendar & Reminders:** A visual monthly calendar to track exams and study sessions. Utilizes the browser's Notification API to alert users 5 minutes before a session and 1 day before an exam.
* **Offline Resiliency:** An event-listener-driven offline banner ensures users know when connectivity drops, though core application functions remain fully operational locally.

## 🛠 Tech Stack
AcadVault is a testament to the power of modern native web features.
* **Structure:** Semantic `HTML5`
* **Styling:** `CSS3` 
  * Custom properties (variables) for theme management.
  * Flexbox and CSS Grid for complex, responsive layouts.
  * Media queries for a seamless mobile experience (includes a dedicated mobile bottom-nav).
  * Keyframe animations for modals and alert banners.
* **Logic & Functionality:** Vanilla `JavaScript (ES6+)`
  * **Storage:** `localStorage` for persistent, client-side data management.
  * **Security:** Native `crypto.subtle.digest` for asynchronous password hashing.
  * **Timing:** `setInterval` and `setTimeout` for the real-time Pomodoro engine and session notification checkers.
  * **APIs:** Native `Notification` API for system-level alerts.

## 🔄 Application Workflow & Architecture
AcadVault operates entirely in the browser, routing views and managing state dynamically:

1. **Initialization & Auth (`app.js`):** On load, the app checks `localStorage` for an active, unexpired session ticket. If absent, the user is routed to the Auth Screen. Passwords are salted and hashed via SHA-256 before validation.
2. **State Management:** Once authenticated, the user's data object (containing sessions, subjects, timer stats, and calendar events) is loaded into memory (`D` object). All subsequent actions mutate this object and trigger a `save()` function to sync with `localStorage`.
3. **DOM Routing:** Navigation is handled by a custom `go(id)` function that toggles `.active` classes on HTML wrapper elements (`#page-dashboard`, `#page-planner`, etc.), simulating SPA routing instantly.
4. **The Background Engine:** A silent interval loop (`runSessionCheck`) runs every 30 seconds to evaluate upcoming sessions against the current system time, triggering UI alerts and system notifications when a scheduled session or meeting is imminent.

## 🎯 Use Cases
* **Students:** Perfect for tracking daily study hours, managing upcoming exams, and executing deep-work sessions using the Pomodoro technique.
* **Self-Taught Learners:** Ideal for organizing self-directed learning paths across various subjects and maintaining consistency through the streak mechanism.
* **Offline Environments:** Because data is stored locally, AcadVault functions perfectly in environments with unstable or restricted internet access (like libraries or commute trips).

## 📥 Installation & Setup
Because AcadVault is entirely client-side, no local server, Node.js environment, or database setup is required.

1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/AcadVault.git](https://github.com/yourusername/AcadVault.git)