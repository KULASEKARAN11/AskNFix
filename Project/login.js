
document.addEventListener("DOMContentLoaded", async () => {
    const loginForm = document.getElementById("loginForm");
  
    if (loginForm) {
        loginForm.addEventListener("submit", async function (event) {
            event.preventDefault();
  
            const rollno = document.getElementById("rollno").value;
            const password = document.getElementById("password").value;
  
            if (!rollno || !password) {
                alert("Please fill in all fields!");
                return;
            }
  
            try {
                const response = await fetch("http://localhost:3000/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify({ rollno, password })
                });
  
                const data = await response.json();
                console.log("Login response:", data);
  
                if (data.success) {
                    localStorage.setItem("user", JSON.stringify(data.user));
  
                    const user1 = JSON.parse(localStorage.getItem("user"));
  
                    if (data.user.residing_status === "Hosteller") {
                        if (Array.isArray(data.user.roommates)) {
                            localStorage.setItem("roommates", JSON.stringify(data.user.roommates));
                            localStorage.setItem("hostelroomno",JSON.stringify(data.user.roomno));
                        }
  
                        if (Array.isArray(data.user.appliances)) {
                            console.log("Saving appliances:", data.user.appliances); // 🆕 Log for verification
                            localStorage.setItem("appliances", JSON.stringify(data.user.appliances));
                        }
                    }
  
                    if (data.user.residing_status === "Hosteller") {
                        window.location.href = "Homepage.html";
                    } else if (data.user.residing_status === "Day Scholar") {
                        window.location.href = "Homepage1.html";
                    } else {
                        alert("Unknown residing status!");
                    }
                } else {
                    alert("Login failed: " + data.message);
                }
            } catch (error) {
                console.error("Error during login:", error);
                alert("Error logging in. Please try again.");
            }
        });
    }
  });

  