document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("file-upload");
  const statsSection = document.querySelector(".file-analysis .stats");
  const messageElement = document.getElementById("message");

  // Stats containers
  const fileNameElement = statsSection.children[0].querySelector("span");
  const fileSizeElement = statsSection.children[1].querySelector("span");
  const fileTypeElement = statsSection.children[2].querySelector("span");
  const isMalware = statsSection.children[3].querySelector("span");

  const btn = document.getElementById("file-upload-btn");
  const h1 = document.getElementById("h1");
  const h2 = document.getElementById("h2");
  const header = document.getElementById("header");
  const label = document.getElementById("label");
  const svg = document.querySelector('.upload-container svg');
  const img = document.getElementById("main");

  fileInput.addEventListener("change", (event) => {
      const file = event.target.files[0]; // Get the first selected file

      if (file) {
          const fileExtension = file.name.split('.').pop().toLowerCase();
          let fileType = "Unknown";

          if (["exe", "dll", "bat"].includes(fileExtension)) {
              if (fileExtension == "exe")
                  fileType = "Executable";
              else if (fileExtension == "dll")
                  fileType = "Dynamic Link Library";
              else
                  fileType = "Batch File";
          }

          // Update stats section with file details
          fileNameElement.textContent = `Name: ${file.name}`;
          fileSizeElement.textContent = `Size: ${(file.size / (1024 * 1024)).toFixed(2)} MB`;
          fileTypeElement.textContent = `Type: ${fileType}`;
          isMalware.textContent = `Check it`;
      } else {
          // Handle no file selected
          uploadedFilesSection.textContent = `No file selected`;
          fileNameElement.textContent = 'Name: -';
          fileSizeElement.textContent = 'Size: -';
          fileTypeElement.textContent = 'Type: -';
          isMalware.textContent = `N/A`;
      }
  });

  btn.addEventListener("click", async (event) => {
      event.preventDefault();

      const file = fileInput.files[0];
      if (!file) {
          messageElement.textContent = "Please select a file first!";
          return;
      }

      const formData = new FormData();
      formData.append("ft", file);

      try {
          const response = await fetch("/upload", {
              method: "POST",
              body: formData,
          });

          const result = await response.json();

          if (result.error) {
              messageElement.textContent = result.error;
          } else if (result.result === "Malware") {
              img.style.backgroundImage = 'url("/static/images/Red.webp")';
              header.style.backgroundColor = 'red';
              label.style.display = 'none';
              h1.style.backgroundColor = 'red';
              h2.style.color = 'red';
              h2.textContent = "Malware Detected";
              btn.style.display = 'none';
              isMalware.style.color = 'red';
              isMalware.textContent = `Malware`;
              fileNameElement.style.color = 'red';
              fileSizeElement.style.color = 'red';
              fileTypeElement.style.color = 'red';
          } else {
              img.style.backgroundImage = 'url("/static/images/Green.webp")';
              header.style.backgroundColor = 'green';
              label.style.display = 'none';
              h1.style.backgroundColor = 'green';
              h2.style.color = 'green';
              h2.textContent = "Your File is Safe";
              btn.style.display = 'none';
              isMalware.style.color = 'green';
              isMalware.textContent = `Not a Malware`;
              fileNameElement.style.color = 'green';
              fileSizeElement.style.color = 'green';
              fileTypeElement.style.color = 'green';
          }
      } catch (error) {
          messageElement.textContent = "An error occurred. Please try again.";
      }
  });
});
