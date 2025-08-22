/**
 * @name Environment File Detection
 * @description Detecta archivos .env que pueden contener información sensible
 * @id js/env-file-detection
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-file
 *       environment
 */

import javascript

/**
 * Holds if `file` is an environment file (e.g., .env, .env.local, .env.production)
 */
predicate isEnvFile(File file) {
  file.getBaseName().matches("%env%") or
  file.getExtension() = "env"
}

/**
 * Holds if `file` contains potentially sensitive environment variables
 */
predicate containsSensitiveEnvVars(File file) {
  exists(string content |
    content = file.getFileContent() and
    (
      content.matches("%API_KEY%") or
      content.matches("%SECRET%") or
      content.matches("%PASSWORD%") or
      content.matches("%TOKEN%") or
      content.matches("%DATABASE_URL%") or
      content.matches("%MONGODB_URI%") or
      content.matches("%JWT_SECRET%") or
      content.matches("%AWS_%") or
      content.matches("%GOOGLE_%") or
      content.matches("%FACEBOOK_%") or
      content.matches("%TWITTER_%") or
      content.matches("%GITHUB_%") or
      content.matches("%STRIPE_%") or
      content.matches("%PAYPAL_%")
    )
  )
}

from File envFile
where isEnvFile(envFile)
select envFile, 
       "Environment file detected: " + envFile.getRelativePath() + 
       (if containsSensitiveEnvVars(envFile) then 
         ". This file may contain sensitive information." 
       else 
         ". Review this file for sensitive data."
       ),
       if containsSensitiveEnvVars(envFile) then 
         "High" 
       else 
         "Medium"
