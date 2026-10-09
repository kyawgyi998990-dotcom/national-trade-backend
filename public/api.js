
async function ntApiRequest(path, method = "GET", body = null) {

    const options = {
        method: method,
        credentials: "same-origin"
    };

    if (body !== null) {
        options.headers = {
            "Content-Type": "application/json"
        };

        options.body = JSON.stringify(body);
    }

    const response = await fetch("/api/" + path, options);

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.message || "Request failed");
    }

    return data;
}
