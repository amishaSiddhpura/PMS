<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
<style>
.main{
color:#286090;
text-align:center;
}
</style>
    <title>Log in with your credentials</title>

    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head>

<body>

<div class="container">
<div class="main" >

<h1>Project Management System</h1>
</div>
    <center>
    <form method="POST" action="${contextPath}/login" class="form-signin">
        <h2 class="form-heading">Log in</h2>

            <div class="form-group ${error != null ? 'has-error' : ''}">
                <span>${msg}</span>
                <input name="username" type="text" class="form-control" placeholder="Username"
                       autofocus="true" style="width: 255px; margin-bottom: 25px;"/>
                <input name="password" type="password" class="form-control" placeholder="Password" style="width: 255px;margin-bottom: 5px;"/>
                <span style="color: red; margin-bottom: 10px;">${errorMsg}</span><br>

                <button class="btn btn-lg btn-primary btn-block" type="submit" style="width: 255px; margin-bottom: 5px;"/">Log In</button>
            </div>
    </form>
    </center>

</div>
<!-- /container -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css"></script></body>
</html>
