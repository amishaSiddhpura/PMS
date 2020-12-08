<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Show Projects</title>
   <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <%-- <link rel="stylesheet" href="css/w3.css" type="text/css">--%>

</head>
<body>
<jsp:include page="menu.jsp" />
<center>
<h1 style="color: red;">Show All Projects</h1>

    <table class="w3-table-all w3-card-4">
        <tr>
            <th style="text-align: center">PROJECT ID</th>
            <th style="text-align: center">TITLE</th>
            <th style="text-align: center">DESCRIPTION</th>
            <th style="text-align: center">START TIME</th>
            <th style="text-align: center">END TIME</th>
           <c:if test="${userRole eq '[ROLE_ADMIN]'}">
                             <th style="text-align: center">EDIT</th>
            <th style="text-align: center">DELETE</th>

                </c:if>
            <th style="text-align: center">ASSIGN MEMBERS</th>
            <th style="text-align: center">SHOW MEMBERS</th>
        </tr>
        <c:forEach var="listValue" items="${projects}">
            <tr>
                <td style="text-align: center">${listValue.id}</td>
                <td style="text-align: center">${listValue.title}</td>
                <td style="text-align: center">${listValue.description}</td>
                <td style="text-align: center">${listValue.startDate}</td>
                <td style="text-align: center">${listValue.endDate}</td>
               <c:if test="${userRole eq '[ROLE_ADMIN]'}">  <td style="text-align: center"><a href="/editProject?id=${listValue.id}">Edit</a> </td>
                <td style="text-align: center"><a href="/deleteProject?id=${listValue.id}">Delete</a> </td></c:if>
                <td style="text-align: center"><a href="/assignMembers?id=${listValue.id}">Assign Members</a> </td>
                <td style="text-align: center"><a href="/showMembers?projectId=${listValue.id}">Show Members</a> </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>