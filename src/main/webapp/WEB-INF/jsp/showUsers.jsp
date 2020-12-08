<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Show Members</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<center>
<h1 style="color: red;">Show All Users</h1>

    <table class="w3-table-all w3-card-4">
        <tr>
            <th style="text-align: center">USERNAME</th>
            <th style="text-align: center">ACTIVE/INACTIVE</th>
            <th style="text-align: center">ROLE</th>
            <th style="text-align: center">EDIT</th>
            <th style="text-align: center">DELETE</th>
        </tr>
        <c:forEach var="listValue" items="${users}">
            <tr>
                <td style="text-align: center">${listValue.username}</td>
                <td style="text-align: center">${listValue.enable eq true ? 'Active' : 'Inactive'}</td>
                <td style="text-align: center">${listValue.role}</td>
                <td style="text-align: center"><a href="/editUser?username=${listValue.username}">Edit</a> </td>
                <td style="text-align: center"><a href="/deleteUser?id=${listValue.id}">Delete</a> </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>