CREATE TABLE articles (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255),
  content TEXT,
  published_by INT,
  published_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_articles_users FOREIGN KEY (published_by) REFERENCES users (id),
);