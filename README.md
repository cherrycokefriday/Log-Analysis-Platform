# Log-Analysis-Platform

<h1>Log Analysis Platform</h1>

  <p>
    This project was made for my distributed systems security course and it basically blends an IDS with SIEM in one web app. Of the useful components are my python event generator (simulating normal day to day events + attack events) and the rule based detection schemes created in PySpark for attack detection.
  </p>

  <h2>Features</h2>
  <ul>
    <li>Security Log Generation and Aggregation</li>
    <li>Automated Log Processing for Suspicious Actions</li>
    <li>SIEM Log Real Time Display</li>
  </ul>



<h2>Setup</h2>

  <h3>1. Clone the Repository</h3>

  <pre><code>
git clone https://github.com/cherrycokefriday/Log-Analysis-Platform.git
cd loganalysis
  </code></pre>

  <h3>2. Start Docker Containers</h3>

  <pre><code>
docker compose up --build
  </code></pre>

  <h3>3. Install Python Dependencies</h3>

  <pre><code>
pip install -r requirements.txt 
  </code></pre>

  <h3>4. Start Spark Services</h3>

  <p>
Start a PySpark session with the required Kafka connector:
</p>

  <pre><code>
docker exec -it spark-client bash
   
/opt/spark/bin/pyspark \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
  --conf spark.jars.ivy=/tmp/.ivy  </code></pre>

  <h3>5. Run Flask Server</h3>

  <pre><code>
python newapp.py
  </code></pre>

  <p>
    The application will be available at:
    <strong>http://localhost:5001</strong>
  </p>

<!--
  <h2>Project Structure</h2>

  <pre><code>
.
├── src/
├── public/
├── tests/
├── package.json
└── README.md
  </code></pre>

  <h2>Roadmap</h2>

  <ul>
    <li>[ ] Add authentication</li>
    <li>[ ] Improve test coverage</li>
    <li>[ ] Add Docker support</li>
    <li>[ ] Deploy production version</li>
  </ul>

  <h2>Contributing</h2>

  <p>
    Contributions are welcome. Please open an issue first to discuss major changes.
  </p>

  <ol>
    <li>Fork the repository</li>
    <li>Create a feature branch</li>
    <li>Commit your changes</li>
    <li>Open a pull request</li>
  </ol>

  <h2>License</h2>

  <p>
    This project is licensed under the MIT License.
  </p>

  <h2>Authors</h2>

  <ul>
    <li>Your Name — Initial work</li>
  </ul>

  <h2>Acknowledgements</h2>

  <ul>
    <li>Inspiration</li>
    <li>Open source community</li>
    <li>Contributors and testers</li>
  </ul>

-->

 
Dashboard Image
<img width="1418" height="835" alt="Screenshot 2026-05-24 174325" src="https://github.com/user-attachments/assets/a3d48f67-9048-427a-9036-73b96c2d069e" />


Suspicious alerts
<img width="1363" height="869" alt="Screenshot 2026-05-24 174236" src="https://github.com/user-attachments/assets/ce1bba7c-a94b-452b-b404-40dc3242ff59" />
