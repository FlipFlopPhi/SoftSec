JC_HOME=java_card_kit-2_2_1

JC_PATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

APP_FOLDER=RationingApplet
APP_MAIN=RationingApplet
APP_PACKAGE=rationingapplet
APP_MAIN_PATH=${APP_FOLDER}/src/${APP_PACKAGE}/${APP_MAIN}

#TERMINAL_FOLDER=TestTerminal
#TERMINAL_MAIN=Main
#TERMINAL_PACKAGE=ratooningsystem
#TERMINAL_MAIN_PATH=${TERMINAL_FOLDER}/src/${TERMINAL_PACKAGE}/${TERMINAL_MAIN}

CONVERTER=java -Djc.home=${JC_HOME} -classpath ${JC_PATH}:${APP_FOLDER}/bin com.sun.javacard.converter.Converter
GP=java -jar gp/gp.jar


all: applet 
	#terminal

applet: ${APP_FOLDER}/bin/${APP_MAIN}.class ${APP_FOLDER}/bin/javacard/applet.cap

${APP_FOLDER}/bin/javacard/applet.cap: ${APP_FOLDER}/bin/${APP_MAIN}.class
	#Converting to cap file	
	${CONVERTER} -v -out CAP -exportpath ${JC_HOME}/api_export_files -classdir ${APP_FOLDER}/bin -d ${APP_FOLDER}/bin \
	-applet 0x12:0x34:0x56:0x78:0x90:0xAB ${APP_PACKAGE}.${APP_MAIN} ${APP_PACKAGE} 0x12:0x34:0x56:0x78:0x90 1.0
	#Uninstall old applet
	${GP} --uninstall ${APP_FOLDER}/bin/${APP_PACKAGE}/javacard/${APP_PACKAGE}.cap
	#Installing applet
	${GP} --install ${APP_FOLDER}/bin/${APP_PACKAGE}/javacard/${APP_PACKAGE}.cap
	
${APP_FOLDER}/bin/${APP_MAIN}.class: ${APP_MAIN_PATH}.java
	#Compiling CalcApplet
	javac -source 1.3 -target 1.1 -d ${APP_FOLDER}/bin -cp ${JC_PATH} ${APP_MAIN_PATH}.java

#${TERMINAL_FOLDER}/bin/${TERMINAL_MAIN}.jar: ${TERMINAL_FOLDER}/bin/${TERMINAL_MAIN}.class
#	cd ${TERMINAL_FOLDER}/bin/ && jar cvfe ${TERMINAL_MAIN}.jar ${TERMINAL_PACKAGE}.${TERMINAL_MAIN} *

#terminal: ${TERMINAL_FOLDER}/bin/${TERMINAL_MAIN}.jar

#${TERMINAL_FOLDER}/bin/${TERMINAL_MAIN}.class: ${TERMINAL_MAIN_PATH}.java
#	javac -d ${TERMINAL_FOLDER}/bin -cp ${JC_HOME} ${TERMINAL_MAIN_PATH}.java

clean:
	rm -rf ${APP_FOLDER}/bin/*
	#rm -rf ${TERMINAL_FOLDER}/bin/*
	${GP} --delete 0x12:0x34:0x56:0x78:0x90
