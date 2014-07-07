GP=$(shell which gnuplot)
EC=$(shell which printf)
LX=$(shell which pdflatex)
UNAME=$(shell uname -s)

CHART_DIR=charts
SOURCES=$(shell ls *.plt)
PDFOBJS=$(SOURCES:.plt=.pdf)
TEXOBJS=$(SOURCES:.plt=.tex)
LOGOBJS=$(SOURCES:.plt=.log)
AUXOBJS=$(SOURCES:.plt=.aux)

all: $(PDFOBJS)

%.pdf: %.plt
	@$(EC) "['$(patsubst %.pdf,%.tex, $@)'][GNUPLOT]\n"
	@$(GP) $(patsubst %.pdf,%.plt, $@) 
	@if [ -e $(patsubst %.pdf,%.tex, $@) ]; then 											\
		$(EC) "['$(patsubst %.pdf,%.tex, $@)'] 'cairolatex' detected\n"; 					\
		if [ -e $(patsubst %.pdf,%-inc.pdf, $@) ]; then 									\
			$(EC) "['$(patsubst %.pdf,%.tex, $@)'] 'mode standalone' detected\n"; 			\
			$(EC) "['$(patsubst %.pdf,%.tex, $@)'][PDFLATEX]\n"; 							\
			$(LX) $(patsubst %.pdf,%.tex, $@); 												\
			rm -f $(patsubst %.pdf,%.tex, $@); 												\
			rm -f $(patsubst %.pdf,%-inc.pdf, $@); 											\
			rm -f $(patsubst %.pdf,%.aux, $@); 												\
			rm -f $(patsubst %.pdf,%.log, $@); 												\
		else 																				\
			$(EC) "['$(patsubst %.pdf,%.tex, $@)'] 'mode input' detected\n"; 				\
			$(EC) "['$(patsubst %.pdf,%.tex, $@)'][SED] fixing path to '$(CHART_DIR)'\n"; 	\
			if [ $(UNAME) == "Darwin" ]; then 												\
				sed 's:\\includegraphics{:\\includegraphics{$(CHART_DIR)/:g' 				\
					$(patsubst %.pdf,%.tex, $@); 											\
			else 																			\
				sed -i -e 's:\\includegraphics{:\\includegraphics{$(CHART_DIR)/:g' 			\
					$(patsubst %.pdf,%.tex, $@); 											\
			fi 																				\
		fi 																					\
	else 																					\
		$(EC) "['$(patsubst %.pdf,%.tex, $@)'] 'cairopdf; detected \n"; 					\
	fi

clean:
	@$(EC) "[*] Cleaning up\n"
	@rm -rf $(PDFOBJS)
	@rm -rf $(TEXOBJS)
	@rm -rf $(AUXOBJS)
	@rm -rf $(LOGOBJS)


