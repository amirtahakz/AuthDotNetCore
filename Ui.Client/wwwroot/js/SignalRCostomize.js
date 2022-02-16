$(document).ready(function () {
    if (Notification.permission !== "granted") {
        Notification.requestPermission();
    }
});
var currentGroupId = 0;
var userId = 0;

var connection = new signalR.HubConnectionBuilder()
    .withUrl("/chat")
    .build();

connection.on("Welcome",
    function (id) {
        userId = id;
    });

connection.on("ReceiveMessage", receive);
connection.on("NewGroup", appendGroup);
connection.on("JoinGroup", joined);
connection.on("ReceiveNotification", sendNotification);
connection.on("Test",
    function (first) {
        console.log(first);
    });

connection.start();

//invoke = فراخوانی کردن

function sendNotification(chat) {
    if (Notification.permission === "granted") {
        console.log(chat.groupId);
        console.log(currentGroupId);
        if (currentGroupId !== chat.groupId) {
            var notification = new Notification(chat.groupName,
                {
                    body: chat.chatBody
                });

        }
    }
}

function receive(chat) {
    $("#messageText").val('');
    if (userId === chat.userId) {
        $(".chats").append(`

        <div class="chat-me">
                        <div class="chat">
                            <span>${chat.userName}</span>
                            <p>${chat.chatBody}</p>
                            <span>${chat.createDate}</span>
                        </div>
                    </div>
                `);
    } else {
        $(".chats").append(`

        <div class="chat-you">
                        <div class="chat">
                            <span>${chat.userName}</span>
                            <p>${chat.chatBody}</p>
                            <span>${chat.createDate}</span>
                        </div>
                    </div>
                `);
    }

}

function SendMessage(event) {
    event.preventDefault();
    var text = $("#messageText").val();
    if (text) {
        connection.invoke("SendMessage", text, currentGroupId);

    } else {
        alert("Error");
    }
}
//function SendMessage(event) {
//    event.preventDefault();
//    var text = $("#messageText").val();
//    connection.invoke("SendMessage", text);
//}

function appendGroup(groupName, token, imageName) {
    if (groupName === "Error") {
        alert("ERROR");
    } else {
        $(".rooms #user_groups ul").append(`
                                                 <li onclick="joinInGroup('${token}')">
                                                ${groupName}
                                                <img src="/image/groups/${imageName}" />
                                                <span></span>
                                            </li>
                                                `);
        $("#exampleModal").modal({ show: false });
    }
}

//function insertGroup(event) {
//    event.preventDefault();
//    var text = $("#groupName").val();
//    if (text) {
//        connection.invoke("CreateGroup", text);
//    }
//}

function insertGroup(event) {
    event.preventDefault();
    console.log(event);
    var groupName = event.target[1].value;
    var imageFile = event.target[2].files[0];
    var formData = new FormData();
    formData.append("GroupName", groupName);
    formData.append("ImageFile", imageFile);

    $.ajax({
        url: "/home/CreateGroup",
        type: "post",
        data: formData,
        encytype: "multipart/form-data",
        processData: false,
        contentType: false
    });
}


function search() {
    var text = $("#search_input").val();
    if (text) {
        $("#search_result").show();
        $("#user_groups").hide();
        $.ajax({
            url: "/home/search?title=" + text,
            type: "get"
        }).done(function (data) {
            $("#search_result ul").html("");
            for (var i in data) {
                if (data[i].isUser) {
                    $("#search_result ul").append(`
                                 <li onclick="joinInPrivateGroup(${data[i].token})">
                                            ${data[i].title}
                                            <img src="/img/${data[i].imageName}" />
                                            <span></span>
                                        </li>
                        `);
                } else {
                    $("#search_result ul").append(`
                                 <li onclick="joinInGroup('${data[i].token}')">
                                            ${data[i].title}
                                            <img src="/image/groups/${data[i].imageName}" />
                                            <span></span>
                                        </li>

                        `);
                }
            }

        });
    } else {
        $("#search_result").hide();
        $("#user_groups").show();
    }
}

function joined(group, chats) {
    $(".header").css("display", "block");
    $(".footer").css("display", "block");
    $(".header h2").html(group.groupTitle);
    $(".header img").attr("src", `/image/groups/${group.imageName}`);
    currentGroupId = group.id;
    $(".chats").html("");
    for (var i in chats) {
        var chat = chats[i];
        if (userId === chat.userId) {
            $(".chats").append(`

        <div class="chat-me">
                        <div class="chat">
                            <span>${chat.userName}</span>
                            <p>${chat.chatBody}</p>
                            <span>${chat.createDate}</span>
                        </div>
                    </div>
                `);
        } else {
            $(".chats").append(`

        <div class="chat-you">
                        <div class="chat">
                            <span>${chat.userName}</span>
                            <p>${chat.chatBody}</p>
                            <span>${chat.createDate}</span>
                        </div>
                    </div>
                `);
        }
    }
}

function joinInGroup(token) {
    connection.invoke("JoinGroup", token, currentGroupId);
}

function joinInPrivateGroup(receiverId) {
    connection.invoke("JoinPrivateGroup", receiverId, currentGroupId);
}

//async function Start() {
//    try {
//        await connection.start();
//        $(".disConnect").show();

//    } catch (e) {
//        $(".disConnect").hide();
        
//        setTimeout(Start, 6000);
//    }
//}

//connection.onclose(Start);
//Start();