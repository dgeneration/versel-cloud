function togglePasswordVisibility() {
    var passwordInput = document.getElementById("password");
    var ConfrimPasswordInput = document.getElementById("confirm_password");
    var passwordToggle = document.querySelector(".password-toggle");

    if (passwordInput.type === "password") {
        passwordToggle.src = "/static/img/open_eye.svg";
        passwordInput.type = "text";
        if (ConfrimPasswordInput) {
            ConfrimPasswordInput.type = "text";
        }
        
    } else {
        passwordToggle.src = "/static/img/close_eye.svg";
        passwordInput.type = "password";
        if (ConfrimPasswordInput) {
            ConfrimPasswordInput.type = "password";
        }
    }
}

function confirmDelete(username) {
    return confirm('Are you sure you want to delete user ' + username + '?');
}