import Dependencies._
import sbt.{Developer, ScmInfo, StdoutOutput, url}

lazy val akkaVersion = "2.+"

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.github.shafiquejamal",
      scalaVersion := "2.11.11",
      version      := "0.0.3"
    )),
    name := "simple-websocket-authenticator",
    libraryDependencies ++= Seq(
      "com.typesafe.akka" %% "akka-actor" % akkaVersion,
      "com.typesafe.akka" %% "akka-testkit" % akkaVersion % Test,
      "com.github.shafiquejamal" %% "utils" % "0.0.4",
      "com.github.shafiquejamal" %% "utils-test" % "0.0.4" % Test,
      "com.github.shafiquejamal" %% "access-api" % "0.0.22",
      "org.scalamock" %% "scalamock" % "4.1.0" % Test,
			scalaTest % Test
		)
  )

outputStrategy := Some(StdoutOutput)

useGpg := true
pomIncludeRepository := { _ => false }

licenses := Seq("BSD-style" -> url("http://www.opensource.org/licenses/bsd-license.php"))

homepage := Some(url("https://github.com/shafiquejamal/simple-authenticator-actor"))

scmInfo := Some(
  ScmInfo(
    url(
      "https://github.com/shafiquejamal/simple-authenticator-actor"),
      "scm:git@github.com:shafiquejamal/simple-authenticator-actor.git"
    )
  )

developers := List(
  Developer(
    id    = "shafiquejamal",
    name  = "Shafique Jamal",
    email = "admin@eigenroute.com",
    url   = url("http://eigenroute.com")
    )
)

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

publishArtifact in Test := false
