import Dependencies._

lazy val akkaVersion = "2.+"

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.github.shafiquejamal",
      scalaVersion := "2.11.11",
      version      := "0.0.1"
    )),
    name := "simple-websocket-authenticator",
    libraryDependencies ++= Seq(
      "com.typesafe.akka" %% "akka-actor" % akkaVersion,
      "com.typesafe.akka" %% "akka-testkit" % akkaVersion % Test,
      "com.github.shafiquejamal" %% "utils" % "[0.0.4,)",
      "com.github.shafiquejamal" %% "utils-test" % "[0.0.4,)" % Test,
      "com.github.shafiquejamal" %% "access-api" % "[0.0.13,)",
			scalaTest % Test
		)
  )
